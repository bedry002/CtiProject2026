from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import json
import pathlib

# Creates the web application instance. It listens for incoming HTTP requests, i.e. POST.
app = FastAPI()
# Cross-Origin Resource Sharing is a security rule that blocks requests made from one domain to another. >allow_origins=["*"] allows requests from any origin. 
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])

# The path 
PROFILE_PATH = pathlib.Path("Assets/Test-bed Profile.json")

# A GET request is sent by the browser when the URL is accessed, returning the >profile_form.html file. This allows the user to see the form in their browser.
@app.get("/")
async def serve_form():
    return FileResponse("profile_form.html")

# The submision button in the HTML of profile_form sends a POST request via the browser to /submit-profile which contains the clients profile in JSON format. 
# This function receives that JSON and writes it to Assets/Test-bed Profile.json, overwriting whatever was there. It also returns {"status": "ok"} back to the browser.
@app.post("/submit-profile")
async def submit_profile(request: Request):
    payload = await request.json()
    PROFILE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"status": "ok", "message": "Profile updated"}