#!/usr/bin/env bash
set -e
uvicorn form_api:app --host 0.0.0.0 --port 8000 &
cloudflared tunnel --url http://localhost:8000
