import sys
from time import time
import os

from fastapi import FastAPI
from fastapi.responses import Response

# replace the default fastapi logger with our logger that only logs errors
from loguru import logger

from .routes import admin, file, other, upload

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

app = FastAPI()

worker_start_time = time()

sys.tracebacklimit = 5  # limit tracebacks to a normal length


@app.exception_handler(500)
async def internal_error_reporter(request, exc):
    logger.opt(exception=exc).error(f"Caught Internal Error - request: {request.url}")
    return Response(status_code=500)

app.include_router(admin.router)
app.include_router(other.router)
app.include_router(upload.router)
app.include_router(file.router)
