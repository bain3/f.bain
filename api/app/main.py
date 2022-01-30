from fastapi import FastAPI

from .routes import admin, file, other, upload

app = FastAPI()

app.include_router(admin.router)
app.include_router(other.router)
app.include_router(upload.router)
app.include_router(file.router)
