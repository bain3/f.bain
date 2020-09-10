"""
This is basically all of f.bain. Very simple.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
import uuid
import hashlib
import aiofiles
import redis as redis_
from .CONSTANTS import REDIS

redis = redis_.Redis(host=REDIS['host'], port=REDIS['port'], db=REDIS['db'], password=REDIS['password'])

app = FastAPI()


@app.post("/")
async def create_file(file: UploadFile = File(None)):
    uuid_ = hashlib.sha1(uuid.uuid4().bytes).hexdigest()[:8]
    redis.set("filename-"+str(uuid_), file.filename)
    async with aiofiles.open("/mount/"+str(uuid_), 'wb+') as f:
        await f.write(await file.read())
    return {"uuid": str(uuid_), "filename": file.filename}


@app.get("/{uuid_}")
async def get_file(uuid_: str):
    filename = redis.get("filename-"+uuid_)
    if not filename:
        raise HTTPException(status_code=404, detail="File was not found.")
    return FileResponse("/mount/"+uuid_, filename=filename.decode())
