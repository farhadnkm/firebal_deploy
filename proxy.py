"""
proxy.py — Thin proxy that hides the RunPod API key from browsers.
"""
import os
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

RUNPOD_API_KEY = os.environ["RUNPOD_API_KEY"]
ENDPOINT_ID = os.environ["RUNPOD_ENDPOINT_ID"]
LAB_PASSWORD = os.environ.get("LAB_PASSWORD", "")
RUNPOD_BASE = f"https://api.runpod.ai/v2/{ENDPOINT_ID}"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

app.mount("/static", StaticFiles(directory="static"), name="static")

if LAB_PASSWORD:
    @app.middleware("http")
    async def check_lab_password(request: Request, call_next):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        pw = (request.headers.get("X-Lab-Password")
              or request.query_params.get("pw", ""))
        if pw != LAB_PASSWORD:
            return Response("Unauthorized", status_code=401)
        return await call_next(request)


# ── RunPod proxy endpoints ────────────────────────────────────────────────
@app.post("/api/run")
async def submit(request: Request):
    body = await request.json()
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(
            f"{RUNPOD_BASE}/run",
            json=body,
            headers={"Authorization": f"Bearer {RUNPOD_API_KEY}",
                     "Content-Type": "application/json"},
        )
    return JSONResponse(r.json(), status_code=r.status_code)


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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
