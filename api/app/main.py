"""
This is basically all of f.bain. Very simple.
"""
import binascii
from random import choice
from time import time
from base64 import b64decode, b64encode
import secrets
import os
import json

from fastapi import FastAPI, HTTPException, Body, Header, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
import aiofiles
import redis as redis_
from starlette.staticfiles import StaticFiles

from . import CONSTANTS

redis = redis_.Redis(host=CONSTANTS.REDIS['host'],
                     port=CONSTANTS.REDIS['port'],
                     db=CONSTANTS.REDIS['db'],
                     password=CONSTANTS.REDIS['password'])
redis.set("initial", "something")

app = FastAPI()
app.mount("/static", StaticFiles(directory="/static/", html=True))

worker_start_time = time()


@app.post("/new")
async def create_file(request: Request, x_metadata: str = Header("")):
    try:
        if not x_metadata:
            raise binascii.Error
        metadata = b64decode(x_metadata)
    except binascii.Error:
        raise HTTPException(status_code=400, detail="X-Metadata header badly formed.")
    # get a new uuid
    uuid = 'initial'
    while redis.exists(uuid):
        uuid = ''.join([choice("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$–_.+!*‘(),") for i in
                        range(5)])
    print(metadata)
    redis.set("metadata-" + uuid, metadata)
    revocation_token = b64encode(secrets.token_bytes(18))
    redis.set("revocation-" + uuid, revocation_token)
    redis.incr("count")
    async with aiofiles.open("/mount/upload/" + uuid.encode().hex(), 'wb+') as f:
        await f.write(await request.body())
    return {"uuid": uuid, "revocation_token": revocation_token}


@app.get("/status")
async def get_status(authorization: str = Header(None)):
    # optionally can be protected with a token, but i don't see the point
    if CONSTANTS.STATUS_TOKEN and not secrets.compare_digest(CONSTANTS.STATUS_TOKEN, authorization):
        raise HTTPException(status_code=401)

    DIR = '/mount/upload/'
    return {
        "files": int(redis.get("count")),
        "total_disk_usage": sum([os.path.getsize(DIR+f) for f in os.listdir(DIR) if os.path.isfile(DIR+f)]),
        "worker_up_time": time() - worker_start_time
    }


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
async def get_raw(uuid: str):
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        raise HTTPException(status_code=404, detail="File was not found.")
    async with aiofiles.open("/mount/upload/" + uuid.encode().hex(), 'rb') as f:
        return Response(await f.read(), media_type="application/octet-stream", status_code=200)


@app.delete("/{uuid}")
async def delete_file(uuid: str, body: dict = Body({"revocation_token": ""})):
    if not redis.exists("revocation-" + uuid):
        raise HTTPException(status_code=404)

    if redis.get("revocation-" + uuid).decode() != body.get("revocation_token", ""):
        raise HTTPException(status_code=401, detail="ID and token combination is invalid.")

    redis.delete("revocation-" + uuid, "metadata-" + uuid)
    redis.decr("count")

    path = "/mount/upload/" + uuid.encode().hex()
    if path == "/mount/upload/":
        raise HTTPException(status_code=400, detail="no.")
    os.remove(path)

    return {"status": "ok"}

