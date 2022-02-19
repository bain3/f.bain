from typing import List

from pydantic import BaseModel, validator


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
    content_length: int

    @validator("salt")
    def salt_must_be_32_bytes(cls, v):
        if len(v) != 32:
            raise ValueError("Salt must be 32 bytes long")
        return v

    @validator("filename")
    def filename_must_be_shorter_than_1024_chars(cls, v):
        if len(v) >= 1024:
            raise ValueError("Filename must be shorter than 1024 characters")
        return v


class SessionToken(BaseModel):
    session_token: str
