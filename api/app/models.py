from typing import List

from pydantic import BaseModel


class StatusResponse(BaseModel):
    files: int
    total_disk_usage: int
    worker_up_time: int


class FileSizeLimitResponse(BaseModel):
    max: int


class Expiration(BaseModel):
    expires_at: int


class FileMeta(BaseModel):
    salt: List[int]
    filename: str


class FileMetaUpload(FileMeta):
    content_length: int


class SessionToken(BaseModel):
    session_token: str
