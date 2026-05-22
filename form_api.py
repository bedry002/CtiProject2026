from __future__ import annotations

import json
import pathlib

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

PROFILE_PATH = pathlib.Path("Assets/Test-bed Profile.json")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/")
async def serve_form() -> FileResponse:
    return FileResponse("profile_form.html")


@app.post("/submit-profile")
async def submit_profile(request: Request) -> dict:
    payload = await request.json()
    PROFILE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"status": "ok", "message": "Profile updated"}
