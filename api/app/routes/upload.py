import os
import logging

import aiofiles
from random import choice
from time import time
import secrets

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from ..db import redis
from ..models import FileMeta, FileMetaUpload

UUID_SIZE = int(os.getenv("UUID_SIZE", 5))
MONTH_SECONDS = 30 * 24 * 60 * 60

router = APIRouter()

logger = logging.getLogger("gunicorn.error")


def generate_unique_uuid() -> str:
    # get a new uuid
    uuid = None
    while uuid is None or redis.exists("metadata-" + uuid):
        uuid = ''.join([choice("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$-_.+!*'(,") for _ in
                        range(UUID_SIZE)])

    return uuid


async def handle_upload(socket: WebSocket, session: str) -> None:
    size = int(redis.hget("session-" + session, "size"))
    block_num = int(redis.hget("session-" + session, "block"))

    if not redis.hsetnx("session-" + session, "lock", 1):
        await socket.send_json({"code": 401, "detail": "Another upload is already in progress"})
        return

    # the temporary file needs to be on a volume because writing to it is a lot faster, also
    # we can move it without copying it
    async with aiofiles.open("/mount/partial/" + session, 'ab+') as f:
        try:
            while size > 0:
                await socket.send_json({"code": 101, "block": block_num})

                block = await socket.receive_bytes()
                await f.write(block)
                block_num += 1
                size -= len(block)

                redis.set("expire-" + session, int(time()) + 7200)  # make the temp file expire in 2 hours
                if not redis.expire("session-" + session, 7200):
                    # the session expired in during uploading
                    size = -1
                    await socket.send_json({"code": 404, "detail": "Session expired"})
        finally:
            if redis.exists("session-" + session):
                redis.hset("session-" + session, "size", size)
                redis.hset("session-" + session, "block", block_num)
                redis.hdel("session-" + session, "lock")

    if size < 0:
        await aiofiles.os.remove("/mount/partial/" + session)
        await socket.send_json({"code": 414, "detail": "Uploaded more data than declared"})
        redis.delete("session-" + session)

    elif size > 0:
        # this only happens if the session expired
        await aiofiles.os.remove("/mount/partial/" + session)

    elif size == 0:
        # finalize upload
        meta = redis.hget("session-" + session, "meta")
        revocation_token = secrets.token_urlsafe(18)
        uuid = generate_unique_uuid()

        redis.set("metadata-" + uuid, meta)
        redis.set("expire-" + uuid, int(time()) + MONTH_SECONDS)
        redis.set("revocation-" + uuid, revocation_token)

        redis.delete("session-" + session)

        await aiofiles.os.rename("/mount/partial/" + session, "/mount/upload/" + uuid.encode().hex())

        await socket.send_json({"code": 200, "uuid": uuid, "revocation_token": revocation_token})


@router.post("/upload")
async def make_session(body: FileMetaUpload):
    if body.content_length > int(redis.get("maxfs")):
        raise HTTPException(status_code=422, detail="File too large")

    session_token = None
    while session_token is None or redis.exists("session-" + session_token):
        session_token = secrets.token_hex(16)
    redis.hset("session-" + session_token, mapping={
        "size": body.content_length,
        "meta": FileMeta.construct(body).json(),
        "block": 0
    })
    redis.expire("session-" + session_token, 7200)

    return {"session_token": session_token}


@router.websocket("/upload/{session_token}")
async def session_upload(socket: WebSocket, session_token: str):
    await socket.accept()
    if not redis.exists("session-" + session_token):
        await socket.send_json({"code": 404, "detail": "Session does not exist"})
        await socket.close(1000)
        return
    try:
        await handle_upload(socket, session_token)
        logger.info("websocket handled")
    except WebSocketDisconnect:
        pass
    else:
        await socket.close(1000)
