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
    return {
        "files": int(redis.get("count")),
        "total_disk_usage": sum([os.path.getsize(dir_ + f) for f in os.listdir(dir_) if os.path.isfile(dir_ + f)]),
        "worker_up_time": time() - worker_start_time
    }


@router.get("/max-filesize", response_model=FileSizeLimitResponse)
async def get_max_filesize():
    return {"max": int(redis.get('maxfs'))}
