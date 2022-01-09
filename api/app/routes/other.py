import os
import secrets
from time import time

from fastapi import APIRouter, HTTPException, Header

from ..db import redis
from ..models import StatusResponse, FileSizeLimitResponse

router = APIRouter()

worker_start_time = time()

STATUS_TOKEN = os.getenv("STATUS_TOKEN", "")


@router.head("/status")
def head_status():
    return


@router.get("/status", response_model=StatusResponse)
def get_status(authorization: str = Header(None)):
    # optionally can be protected with a token, but I don't see the point
    if STATUS_TOKEN and (authorization is None or not secrets.compare_digest(STATUS_TOKEN, authorization)):
        raise HTTPException(status_code=401)

    dir_ = '/mount/upload/'
    count = 0
    total_size = 0
    file: os.DirEntry
    for file in os.scandir(dir_):
        if file.is_file():
            total_size += file.stat().st_size
            count += 1

    return {
        "files": count,
        "total_disk_usage": total_size,
        "worker_up_time": time() - worker_start_time
    }


@router.get("/max-filesize", response_model=FileSizeLimitResponse)
async def get_max_filesize():
    return {"max": int(redis.get('maxfs'))}
