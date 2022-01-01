from typing import Optional, List

from pydantic import BaseModel


class StatusResponse(BaseModel):
    files: int
    total_disk_usage: int
    worker_up_time: int


class FileSizeLimitResponse(BaseModel):
    max: int


class DeleteFileRequest(BaseModel):
    revocation_token: Optional[str]
    admin_token: Optional[str]


class FileMeta(BaseModel):
    salt: List[int]
    filename: str
