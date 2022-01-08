from typing import Optional, List

from pydantic import BaseModel


class StatusResponse(BaseModel):
    files: int
    total_disk_usage: int
    worker_up_time: int


class FileSizeLimitResponse(BaseModel):
    max: int


class ExpirationRequest(BaseModel):
    expires_at: int


class FileMeta(BaseModel):
    salt: List[int]
    filename: str


class ExpirationResponse(BaseModel):
    expires_at: int
