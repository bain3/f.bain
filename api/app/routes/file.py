import json
import os
import secrets
import time

from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import HTMLResponse, FileResponse
import aiofiles

from ..db import redis
from ..models import FileMeta, Expiration

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

router = APIRouter()


def check_token(token: str, uuid: str):
    if not redis.exists("file:" + uuid):
        raise HTTPException(status_code=404)

    if (not ADMIN_TOKEN or not secrets.compare_digest(token, ADMIN_TOKEN)) \
            and not secrets.compare_digest(token, redis.hget("file:" + uuid, "revocation").decode()):
        raise HTTPException(status_code=401, detail="ID and token combination is invalid.")


@router.get("/{uuid}", summary="Get HTML for file download and decryption", response_class=HTMLResponse)
async def get_file(uuid: str):
    meta = redis.hget("file:" + uuid, "metadata")
    if not meta:
        raise HTTPException(status_code=404, detail="Meta not found.")
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        redis.delete("file:" + uuid)
        raise HTTPException(status_code=404, detail="File not found.")
    async with aiofiles.open("/mount/static/index.html", 'r') as f:
        return HTMLResponse(await f.read())


@router.get("/{uuid}/meta", response_model=FileMeta, summary="Get file metadata")
def get_meta(uuid: str):
    meta = redis.hget("file:" + uuid, "metadata")
    if not meta:
        raise HTTPException(status_code=404, detail="Meta not found.")

    return FileMeta.construct(**json.loads(meta))


@router.get("/{uuid}/raw", summary="Get raw file data", response_class=FileResponse)
@router.head("/{uuid}/raw", summary="Get file size")
def get_raw(uuid: str):
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        raise HTTPException(status_code=404, detail="File not found.")

    return FileResponse("/mount/upload/" + uuid.encode().hex())


@router.delete("/{uuid}", summary="Delete a file")
async def delete_file(uuid: str, authorization: str = Header("")):
    check_token(authorization, uuid)

    redis.delete("file:" + uuid)

    path = "/mount/upload/" + uuid.encode().hex()
    await aiofiles.os.remove(path)


@router.get("/{uuid}/expire", summary="Get expiration time", response_model=Expiration)
async def get_expiration(uuid: str, authorization: str = Header("")):
    check_token(authorization, uuid)

    ex = int(time.time())+redis.ttl("file:" + uuid)
    return Expiration(expires_at=ex)


@router.put("/{uuid}/expire", summary="Set new expiration time")
async def set_expiration(uuid: str, body: Expiration, authorization: str = Header("")):
    check_token(authorization, uuid)

    if body.expires_at < 0:
        redis.persist("file:" + uuid)
    elif body.expires_at < time.time():
        raise HTTPException(status_code=400, detail="Time is in the past")
    else:
        redis.expireat("file:" + uuid, body.expires_at)
