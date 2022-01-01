import binascii
import sys
from random import choice
from time import time
from base64 import b64decode
import secrets
import os
import json

from fastapi import FastAPI, HTTPException, Body, Header, Request
from fastapi.responses import HTMLResponse, FileResponse, Response

import aiofiles
from redis import Redis

# replace the default fastapi logger with our logger that only logs errors
from loguru import logger

REDIS = {
    "host": "redis",
    "port": 6379,
    "db": 0,
    "password": None
}
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 5 * 1000 ^ 2 * 100))
UUID_SIZE = int(os.getenv("UUID_SIZE", 5))
STATUS_TOKEN = os.getenv("STATUS_TOKEN", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

redis = Redis(host=REDIS['host'],
              port=REDIS['port'],
              db=REDIS['db'],
              password=REDIS['password'])

redis.setnx("count", 0)
redis.set("maxfs", MAX_FILE_SIZE)

app = FastAPI()

worker_start_time = time()

sys.tracebacklimit = 5  # limit tracebacks to a normal length


@app.exception_handler(500)
async def internal_error_reporter(request, exc):
    logger.exception("Caught Internal Error")
    return Response(status_code=500)


@app.post("/new")
async def create_file(request: Request, x_metadata: str = Header(""),
                      content_len: int = Header(None, alias="content-length")):
    # Verify metadata header
    try:
        if not x_metadata:
            raise binascii.Error
        metadata = b64decode(x_metadata)
    except binascii.Error:
        raise HTTPException(status_code=400, detail="X-Metadata header badly formed.")

    # Catch large requests asap
    max_filesize = int(redis.get("maxfs"))
    if not content_len or content_len > max_filesize:
        raise HTTPException(status_code=413, detail="The file is too large")

    # get a new uuid
    uuid = None
    while uuid is None or redis.exists(uuid):
        uuid = ''.join([choice("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$-_.+!*'(,") for _ in
                        range(UUID_SIZE)])

    # save the file
    total = 0
    aborted = False
    async with aiofiles.open("/mount/upload/" + uuid.encode().hex(), 'wb+') as f:
        async for chunk in request.stream():
            total += len(chunk)
            if total > max_filesize:
                aborted = True
                break

            await f.write(chunk)
    if aborted:
        # clean up if aborted, return error code
        await aiofiles.os.remove("/mount/upload/" + uuid.encode().hex())
        raise HTTPException(status_code=413, detail="The file is too large")

    # save metadata and generate a revocation token
    redis.set("metadata-" + uuid, metadata)
    revocation_token = secrets.token_urlsafe(18)
    redis.set("revocation-" + uuid, revocation_token)

    # update statistics
    redis.incr("count")

    return {"uuid": uuid, "revocation_token": revocation_token}


@app.head("/status")
def head_status():
    return


@app.get("/status")
def get_status(authorization: str = Header(None)):
    # optionally can be protected with a token, but i don't see the point
    if STATUS_TOKEN and (authorization is None or not secrets.compare_digest(STATUS_TOKEN, authorization)):
        raise HTTPException(status_code=401)

    dir_ = '/mount/upload/'
    return {
        "files": int(redis.get("count")),
        "total_disk_usage": sum([os.path.getsize(dir_ + f) for f in os.listdir(dir_) if os.path.isfile(dir_ + f)]),
        "worker_up_time": time() - worker_start_time
    }


@app.get("/max-filesize")
async def get_max_filesize():
    return {"max": int(redis.get('maxfs'))}


@app.post("/max-filesize/{new_max}")
async def set_max_filesize(new_max: str, authorization: str = Header("")):
    if not ADMIN_TOKEN or not secrets.compare_digest(authorization, ADMIN_TOKEN):
        raise HTTPException(status_code=401)

    # convert to bytes
    magnitude = 1
    try:
        magnitude = 1000 ** ("KMGT".index(new_max[-1]) + 1)
        new_max = new_max[:-1]
    except ValueError:
        pass

    try:
        new_max = int(new_max)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid max filesize")

    redis.set("maxfs", int(new_max) * magnitude)
    return {"max": int(redis.get("maxfs"))}


@app.get("/{uuid}")
async def get_file(uuid: str):
    meta = redis.get("metadata-" + uuid)
    if not meta:
        print("meta not found")
        raise HTTPException(status_code=404, detail="Meta not found.")
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        print("file not found")
        redis.delete("metadata-" + uuid)
        raise HTTPException(status_code=404, detail="File not found.")
    async with aiofiles.open("/mount/static/index.html", 'r') as f:
        return HTMLResponse(await f.read())


@app.get("/{uuid}/meta")
def get_meta(uuid: str):
    meta = redis.get("metadata-" + uuid)
    if not meta:
        raise HTTPException(status_code=404, detail="No meta was found.")

    # checking if the meta was formed correctly
    try:
        meta = json.loads(meta)
        if set(meta.keys()) != {"salt", "filename"}:
            print(meta)
            raise json.JSONDecodeError("", "", 0)
    except json.JSONDecodeError:
        # Deleting malformed metadata and returning error
        redis.delete("metadata-" + uuid)
        raise HTTPException(status_code=422, detail="Meta was malformed.")

    return meta


@app.get("/{uuid}/raw")
@app.head("/{uuid}/raw")
def get_raw(uuid: str):
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        raise HTTPException(status_code=404, detail="File was not found.")

    return FileResponse("/mount/upload/" + uuid.encode().hex())


@app.delete("/{uuid}")
async def delete_file(uuid: str, body: dict = Body({"revocation_token": "", "admin_token": ""})):
    if not redis.exists("revocation-" + uuid):
        raise HTTPException(status_code=404)

    if (ADMIN_TOKEN and not secrets.compare_digest(body.get("admin_token", ""), ADMIN_TOKEN)) \
            and not secrets.compare_digest(redis.get("revocation-" + uuid).decode(), body.get("revocation_token", "")):
        raise HTTPException(status_code=401, detail="ID and token combination is invalid.")

    redis.delete("revocation-" + uuid, "metadata-" + uuid)
    redis.decr("count")

    path = "/mount/upload/" + uuid.encode().hex()
    if path == "/mount/upload/":
        raise HTTPException(status_code=400, detail="no.")
    await aiofiles.os.remove(path)

    return {"status": "ok"}
