import os

import aiofiles
from random import choice
from base64 import b64decode
import binascii
from time import time
import secrets

import pydantic
from fastapi import APIRouter, Request, Header, HTTPException

from ..db import redis
from ..models import FileMeta

UUID_SIZE = int(os.getenv("UUID_SIZE", 5))
MONTH_SECONDS = 30 * 24 * 60 * 60

router = APIRouter()


@router.post("/new")
async def create_file(request: Request, x_metadata: str = Header(""),
                      content_len: int = Header(None, alias="content-length")):
    # Verify metadata header
    try:
        if not x_metadata:
            raise binascii.Error
        metadata: FileMeta = FileMeta.parse_raw(b64decode(x_metadata))
    except binascii.Error or pydantic.ValidationError:
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
    redis.set("metadata-" + uuid, metadata.json())
    revocation_token = secrets.token_urlsafe(18)
    redis.set("revocation-" + uuid, revocation_token)

    # default expiration time is one month if not set we assume expiration indefinite
    redis.set("expire-" + uuid, int(time()) + MONTH_SECONDS)

    # update statistics
    redis.incr("count")

    return {"uuid": uuid, "revocation_token": revocation_token}
