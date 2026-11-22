"""Application entry point: creates the app, registers routes, serves the frontend."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.api.routes import router

# backend/app/main.py -> project root is two levels above "app"
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

app = FastAPI(title="AI Cybersecurity Log Analyzer", version="0.7.0")

# Browser-side protection. Uploaded logs are untrusted, so even if a bug let hostile text reach the page,
# this policy stops inline scripts from running. Scripts may only come from this server or the pinned
# Chart.js CDN; the page may only talk to this server; nothing may frame it.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")     # reports are per-upload; never cache them
    return response


# API routes first, so "/api/..." is never swallowed by the static mount.
app.include_router(router)

# Serve the frontend from the same server (no CORS setup needed).
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
