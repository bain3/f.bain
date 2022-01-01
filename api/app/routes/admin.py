# Routes restricted by ADMIN_TOKEN

import os
import secrets

from fastapi import APIRouter, Header, HTTPException

from ..db import redis

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

router = APIRouter()


@router.post("/max-filesize/{new_max}", summary="Set new max file size")
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
