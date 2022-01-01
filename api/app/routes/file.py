import json
import os
import secrets

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
import aiofiles

from ..db import redis
from ..models import DeleteFileRequest, FileMeta

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

router = APIRouter()


@router.get("/{uuid}", summary="Get HTML for file download and decryption", response_class=HTMLResponse)
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


@router.get("/{uuid}/meta", response_model=FileMeta, summary="Get file metadata")
def get_meta(uuid: str):
    meta = redis.get("metadata-" + uuid)
    if not meta:
        raise HTTPException(status_code=404, detail="No meta was found.")

    return FileMeta.construct(**json.loads(meta))


@router.get("/{uuid}/raw", summary="Get raw file data", response_class=FileResponse)
@router.head("/{uuid}/raw", summary="Get file size")
def get_raw(uuid: str):
    if not os.path.exists("/mount/upload/" + uuid.encode().hex()):
        raise HTTPException(status_code=404, detail="File was not found.")

    return FileResponse("/mount/upload/" + uuid.encode().hex())


@router.delete("/{uuid}", summary="Delete a file")
async def delete_file(uuid: str, body: DeleteFileRequest):
    if not redis.exists("revocation-" + uuid):
        raise HTTPException(status_code=404)

    if not (body.revocation_token and secrets.compare_digest(body.revocation_token, redis.get("revocation-" + uuid).decode()))\
            and not (body.admin_token and secrets.compare_digest(body.admin_token, ADMIN_TOKEN)):
        raise HTTPException(status_code=401, detail="ID and token combination is invalid.")

    redis.delete("revocation-" + uuid, "metadata-" + uuid, "expire-" + uuid)
    redis.decr("count")

    path = "/mount/upload/" + uuid.encode().hex()
    await aiofiles.os.remove(path)
