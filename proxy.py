"""
proxy.py — Thin proxy that hides the RunPod API key from browsers.
Includes session-based authentication: login/logout endpoints and protected routes.
"""
import os, uuid, httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from auth import init_db, authenticate_user, create_session, validate_session, revoke_session
from seed_user import create_seed_user

RUNPOD_API_KEY  = os.environ["RUNPOD_API_KEY"]
ENDPOINT_ID     = os.environ["RUNPOD_ENDPOINT_ID"]
LAB_PASSWORD    = os.environ.get("LAB_PASSWORD", "")
RUNPOD_BASE     = f"https://api.runpod.ai/v2/{ENDPOINT_ID}"
HTTPS           = os.environ.get("HTTPS", "false").lower() == "true"
ON_RAILWAY      = os.environ.get("RAILWAY_ENVIRONMENT") is not None

# ── Object storage (S3-compatible) — large-file upload path ────────────────
# Optional: only required if you want to support files too large for
# RunPod's 10 MB /run payload cap. Works with any S3-compatible provider
# (Cloudflare R2, AWS S3, Backblaze B2, MinIO, ...) — point S3_ENDPOINT_URL
# at it. These must be the SAME bucket/credentials configured as env vars
# on the RunPod endpoint (see handler.py), since the worker downloads from
# here too.
S3_BUCKET          = os.environ.get("S3_BUCKET")
S3_ENDPOINT_URL    = os.environ.get("S3_ENDPOINT_URL")
S3_ACCESS_KEY      = os.environ.get("S3_ACCESS_KEY")
S3_SECRET_KEY      = os.environ.get("S3_SECRET_KEY")
S3_REGION          = os.environ.get("S3_REGION", "auto")
S3_UPLOAD_URL_TTL  = int(os.environ.get("S3_UPLOAD_URL_TTL", "3600"))  # seconds

_s3_client = None


def _get_s3_client():
    global _s3_client
    if _s3_client is None:
        import boto3
        _s3_client = boto3.client(
            "s3",
            endpoint_url           = S3_ENDPOINT_URL,
            aws_access_key_id      = S3_ACCESS_KEY,
            aws_secret_access_key  = S3_SECRET_KEY,
            region_name            = S3_REGION,
        )
    return _s3_client

# ── Startup diagnostic — log whether S3 config loaded correctly, without
# ever printing the actual secret values. This turns "presigned URL is
# silently malformed" into a one-line answer in the Railway deploy log.
def _s3_config_status() -> str:
    def state(name, val):
        if val is None:
            return f"{name}=<unset>"
        if val == "":
            return f"{name}=<empty string!>"
        return f"{name}=<set, {len(val)} chars>"
    return " ".join([
        state("S3_BUCKET", S3_BUCKET),
        state("S3_ENDPOINT_URL", S3_ENDPOINT_URL),
        state("S3_ACCESS_KEY", S3_ACCESS_KEY),
        state("S3_SECRET_KEY", S3_SECRET_KEY),
    ])

print(f"[proxy] S3 config at startup: {_s3_config_status()}")

# Initialize database on startup
init_db()
create_seed_user("test_user", "test", quiet=True)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Session-based auth middleware ──────────────────────────────────────────
@app.middleware("http")
async def check_session(request: Request, call_next):
    # Skip auth for login/logout endpoints
    if request.url.path in ["/auth/login", "/auth/logout", "/login.html"]:
        return await call_next(request)
    if request.url.path.startswith("/static/"):
        return await call_next(request)

    # Get session cookie
    session_id = request.cookies.get("session_id")

    # Validate session
    if not ON_RAILWAY and (not session_id or not validate_session(session_id)):
        # Not authenticated
        if request.url.path.startswith("/api/"):
            # Legacy: allow /api/ with LAB_PASSWORD header/query param
            if LAB_PASSWORD:
                pw = (request.headers.get("X-Lab-Password")
                      or request.query_params.get("pw", ""))
                if pw == LAB_PASSWORD:
                    return await call_next(request)
            return Response("Unauthorized", status_code=401)
        else:
            # Redirect or return 401 for web routes
            return RedirectResponse(url="/login.html")

    return await call_next(request)

# ── Auth endpoints ─────────────────────────────────────────────────────────
@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")

    if not username or not password:
        return JSONResponse(
            {"error": "username and password required"},
            status_code=400
        )

    user = authenticate_user(username, password)
    if not user:
        return JSONResponse(
            {"error": "invalid username or password"},
            status_code=401
        )

    session_id = create_session(user["id"])
    response = JSONResponse({"success": True, "username": user["username"]})
    response.set_cookie(
        "session_id",
        session_id,
        httponly=True,
        secure=HTTPS,
        samesite="lax",
        max_age=86400
    )
    return response

@app.post("/auth/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        revoke_session(session_id)

    response = JSONResponse({"success": True})
    response.delete_cookie("session_id")
    return response

# ── RunPod proxy endpoints ────────────────────────────────────────────────
@app.post("/api/run")
async def submit(request: Request):
    # Stream the raw request body straight through to RunPod instead of
    # `await request.json()` + `json=body`. The old approach parsed the
    # entire (base64-inflated) payload into a Python dict and then had
    # httpx re-serialize it back to JSON — two extra full copies of the
    # payload in memory on top of the original bytes. This avoids both,
    # but does NOT raise the effective file-size ceiling: RunPod's /run
    # endpoint hard-caps the total payload at 10 MB regardless of how
    # the proxy handles it. For files near or above that limit, route
    # them through object storage instead (see project notes).
    content_type = request.headers.get("content-type", "application/json")
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f"{RUNPOD_BASE}/run",
            content=request.stream(),
            headers={"Authorization": f"Bearer {RUNPOD_API_KEY}",
                     "Content-Type": content_type},
        )
    return JSONResponse(r.json(), status_code=r.status_code)

class UploadUrlRequest(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"

class DownloadUrlRequest(BaseModel):
    key: str

def _missing_s3_config() -> list:
    return [name for name, val in [
        ("S3_BUCKET", S3_BUCKET),
        ("S3_ENDPOINT_URL", S3_ENDPOINT_URL),
        ("S3_ACCESS_KEY", S3_ACCESS_KEY),
        ("S3_SECRET_KEY", S3_SECRET_KEY),
    ] if not val]   # catches both None (unset) and "" (set but blank)

def _s3_unconfigured_response() -> JSONResponse:
    missing = _missing_s3_config()
    return JSONResponse(
        {"error": f"Object storage is misconfigured on this server — "
                  f"missing or empty: {', '.join(missing)}. Check Railway "
                  f"→ Variables and confirm these have actual values, "
                  f"then redeploy. (Current status: {_s3_config_status()})"},
        status_code=501)

@app.post("/api/upload-url")
async def upload_url(req: UploadUrlRequest):
    """Issue a presigned PUT URL so the browser can upload large files
    directly to object storage, bypassing RunPod's /run payload cap.
    The returned `key` should be sent as image_key/psf_key in the job's
    config when calling /api/run, instead of image_b64/psf_b64."""
    if _missing_s3_config():
        return _s3_unconfigured_response()

    # Unique key per upload — avoids collisions between concurrent users
    # and keeps each job's files easy to identify/clean up.
    safe_name = "".join(c for c in req.filename if c.isalnum() or c in "._-") \
                or "upload.tif"
    key = f"uploads/{uuid.uuid4().hex}/{safe_name}"

    client = _get_s3_client()
    url = client.generate_presigned_url(
        "put_object",
        Params={"Bucket": S3_BUCKET, "Key": key,
                "ContentType": req.content_type},
        ExpiresIn=S3_UPLOAD_URL_TTL,
    )
    return {"upload_url": url, "key": key}

@app.post("/api/download-url")
async def download_url(req: DownloadUrlRequest):
    """Issue a presigned GET URL for a result file that handler.py
    uploaded to object storage instead of inlining as result_b64 in
    the job output (RunPod's /run result payload has the same ~10 MB
    cap as the request — see /api/upload-url). The browser fetches the
    actual bytes directly from this URL, bypassing the proxy and
    RunPod entirely for the download step."""
    if _missing_s3_config():
        return _s3_unconfigured_response()

    # Defence in depth: only ever serve objects under results/, even
    # though the key originates from a job we ourselves submitted —
    # a forged key shouldn't be able to read arbitrary bucket contents
    # (e.g. other users' uploads/).
    if not req.key.startswith("results/"):
        return JSONResponse(
            {"error": "Invalid key: downloads are only permitted for "
                      "objects under results/."},
            status_code=400)

    client = _get_s3_client()
    url = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": req.key},
        ExpiresIn=S3_UPLOAD_URL_TTL,
    )
    return {"download_url": url}

@app.get("/api/status/{job_id}")
async def status(job_id: str):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{RUNPOD_BASE}/status/{job_id}",
            headers={"Authorization": f"Bearer {RUNPOD_API_KEY}"},
        )
    return JSONResponse(r.json(), status_code=r.status_code)

@app.get("/api/cancel/{job_id}")
async def cancel(job_id: str):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{RUNPOD_BASE}/cancel/{job_id}",
            headers={"Authorization": f"Bearer {RUNPOD_API_KEY}"},
        )
    return JSONResponse(r.json(), status_code=r.status_code)

@app.get("/api/health")
async def health():
    return {"status": "ok", "endpoint": ENDPOINT_ID}

# ── Serve frontend ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(html_path, encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/login.html", response_class=HTMLResponse)
async def login_page():
    html_path = os.path.join(os.path.dirname(__file__), "static", "login.html")
    with open(html_path, encoding="utf-8") as f:
        return HTMLResponse(f.read())

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)