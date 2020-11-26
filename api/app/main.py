"""
This is basically all of f.bain. Very simple.
"""
import binascii
from random import choice

from fastapi import FastAPI, HTTPException, Body, Header, Request
from starlette.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
import aiofiles
import os
import redis as redis_
from .CONSTANTS import REDIS
import json
from base64 import b64decode

redis = redis_.Redis(host=REDIS['host'], port=REDIS['port'], db=REDIS['db'], password=REDIS['password'])
redis.set("initial", "something")

app = FastAPI()


@app.post("/n")
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
    async with aiofiles.open("/mount/upload/" + uuid.encode().hex(), 'wb+') as f:
        await f.write(await request.body())
    return {"uuid": uuid}


@app.get("/{uuid}")
async def get_file(uuid: str):
    meta = redis.get("metadata-" + uuid)
    if not meta:
        print("meta not found")
        raise HTTPException(status_code=404, detail="File was not found.")
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        print("file not found")
        redis.delete("metadata-" + uuid)
        raise HTTPException(status_code=404, detail="File was not found.")
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
