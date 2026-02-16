"""
Speedtest API - File upload/download with checksum verification.
All endpoints return 404 unless valid API key is provided via X-API-Key header.

Configuration is via environment variables (see .env.example):
  SPEEDTEST_API_KEY  - required, the shared secret
  SPEEDTEST_DOMAIN   - optional, used for DNS self-lookup in /api/whoami
"""

import asyncio
import hashlib
import os
import secrets
import socket
from pathlib import Path

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

API_KEY = os.environ.get("SPEEDTEST_API_KEY", "")
SPEEDTEST_DOMAIN = os.environ.get("SPEEDTEST_DOMAIN", "")
STORAGE_DIR = Path("/data/files")
CLIENT_DIR = Path("/app/client")
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB
CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB for streaming reads
PING_TIMEOUT = 5  # seconds per individual ping target

STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def verify_key(api_key: str | None) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if not api_key or not API_KEY:
        return False
    return secrets.compare_digest(api_key, API_KEY)


def sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


NOT_FOUND = JSONResponse(status_code=404, content={"detail": "Not Found"})


# Override default exception handlers to always return plain 404
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


@app.exception_handler(422)
async def validation_error_handler(request: Request, exc):
    """Mask validation errors as 404 to prevent information leakage."""
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc):
    """Mask FastAPI request validation errors as 404."""
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------

@app.post("/api/upload", response_class=JSONResponse)
async def upload_file(
    request: Request,
    x_api_key: str | None = Header(None),
):
    if not verify_key(x_api_key):
        return NOT_FOUND

    filename = request.headers.get("X-Filename", "upload.bin")
    filename = Path(filename).name
    if not filename:
        filename = "upload.bin"

    dest = STORAGE_DIR / filename
    sha = hashlib.sha256()
    total = 0

    with open(dest, "wb") as f:
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_FILE_SIZE:
                f.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File exceeds 1 GB limit")
            sha.update(chunk)
            f.write(chunk)

    checksum = sha.hexdigest()
    size = dest.stat().st_size

    return {
        "filename": filename,
        "size": size,
        "sha256": checksum,
    }


@app.post("/api/upload-multipart", response_class=JSONResponse)
async def upload_file_multipart(
    file: UploadFile = File(...),
    x_api_key: str | None = Header(None),
):
    """Multipart form upload alternative."""
    if not verify_key(x_api_key):
        return NOT_FOUND

    filename = Path(file.filename or "upload.bin").name
    dest = STORAGE_DIR / filename
    sha = hashlib.sha256()
    total = 0

    with open(dest, "wb") as f:
        while chunk := await file.read(CHUNK_SIZE):
            total += len(chunk)
            if total > MAX_FILE_SIZE:
                f.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File exceeds 1 GB limit")
            sha.update(chunk)
            f.write(chunk)

    return {
        "filename": filename,
        "size": dest.stat().st_size,
        "sha256": sha.hexdigest(),
    }


@app.get("/api/download/{filename}")
async def download_file(filename: str, x_api_key: str | None = Header(None)):
    if not verify_key(x_api_key):
        return NOT_FOUND

    safe_name = Path(filename).name
    filepath = STORAGE_DIR / safe_name

    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    checksum = sha256_file(filepath)

    return FileResponse(
        path=str(filepath),
        filename=safe_name,
        media_type="application/octet-stream",
        headers={"X-SHA256": checksum},
    )


@app.get("/api/checksum/{filename}")
async def get_checksum(filename: str, x_api_key: str | None = Header(None)):
    if not verify_key(x_api_key):
        return NOT_FOUND

    safe_name = Path(filename).name
    filepath = STORAGE_DIR / safe_name

    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return {
        "filename": safe_name,
        "size": filepath.stat().st_size,
        "sha256": sha256_file(filepath),
    }


@app.get("/api/list")
async def list_files(x_api_key: str | None = Header(None)):
    if not verify_key(x_api_key):
        return NOT_FOUND

    files = []
    for f in sorted(STORAGE_DIR.iterdir()):
        if f.is_file():
            files.append({"filename": f.name, "size": f.stat().st_size})
    return {"files": files}


@app.delete("/api/delete/{filename}")
async def delete_file(filename: str, x_api_key: str | None = Header(None)):
    if not verify_key(x_api_key):
        return NOT_FOUND

    safe_name = Path(filename).name
    filepath = STORAGE_DIR / safe_name

    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    filepath.unlink()
    return {"deleted": safe_name}


@app.get("/api/client")
async def get_client(x_api_key: str | None = Header(None)):
    """Download the Python client script."""
    if not verify_key(x_api_key):
        return NOT_FOUND

    client_path = CLIENT_DIR / "speedtest_client.py"
    if not client_path.is_file():
        raise HTTPException(status_code=500, detail="Client not available")

    return FileResponse(
        path=str(client_path),
        filename="speedtest_client.py",
        media_type="text/x-python",
    )


# ---------------------------------------------------------------------------
# /api/whoami - Return client IP, reverse DNS, and server-side DNS lookups
# ---------------------------------------------------------------------------

def _reverse_dns(ip: str) -> str:
    """Best-effort reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _forward_dns(hostname: str) -> list[str]:
    """Best-effort forward DNS lookup."""
    if not hostname:
        return []
    try:
        return sorted({addr[4][0] for addr in socket.getaddrinfo(hostname, None)})
    except (socket.gaierror, OSError):
        return []


@app.get("/api/whoami")
async def whoami(request: Request, x_api_key: str | None = Header(None)):
    """Return the client's outgoing IP and related network info."""
    if not verify_key(x_api_key):
        return NOT_FOUND

    # Client IP from X-Forwarded-For (reverse proxy sets this) or direct connection
    forwarded = request.headers.get("x-forwarded-for", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    # Run DNS lookups in a thread to avoid blocking
    loop = asyncio.get_event_loop()
    rdns, server_ip = await asyncio.gather(
        loop.run_in_executor(None, _reverse_dns, client_ip),
        loop.run_in_executor(None, _forward_dns, SPEEDTEST_DOMAIN),
    )

    result = {
        "client_ip": client_ip,
        "reverse_dns": rdns or None,
        "server_dns_lookup": server_ip if server_ip else None,
        "x_forwarded_for": forwarded or None,
        "x_real_ip": request.headers.get("x-real-ip"),
    }
    if SPEEDTEST_DOMAIN:
        result["server_domain"] = SPEEDTEST_DOMAIN

    return result


# ---------------------------------------------------------------------------
# /api/ping - Ping targets supplied by the client
# ---------------------------------------------------------------------------

async def _ping_one(name: str, ip: str) -> dict:
    """Ping a single host with a 5s timeout, return structured result."""
    # Basic IP validation - only allow IPv4/IPv6 addresses, no hostnames
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
        except OSError:
            return {"name": name, "ip": ip, "reachable": False, "detail": "invalid IP address"}

    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", str(PING_TIMEOUT), ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=PING_TIMEOUT + 2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"name": name, "ip": ip, "reachable": False, "detail": "timeout"}

        output = stdout.decode().strip()
        lines = output.splitlines()
        stats = {}
        for line in lines:
            if "packet loss" in line:
                stats["packet_loss"] = line.strip()
            if "rtt" in line or "round-trip" in line:
                stats["rtt"] = line.strip()

        return {
            "name": name,
            "ip": ip,
            "reachable": proc.returncode == 0,
            "return_code": proc.returncode,
            **stats,
        }
    except Exception as e:
        return {"name": name, "ip": ip, "reachable": False, "detail": str(e)}


@app.post("/api/ping")
async def ping_targets(request: Request, x_api_key: str | None = Header(None)):
    """Ping targets supplied by the client in the request body.

    Expected JSON body:
        {"targets": {"MyISP": "1.2.3.4", "Other": "5.6.7.8"}}

    Targets are pinged in parallel with individual 5s timeouts.
    Maximum 10 targets per request.
    """
    if not verify_key(x_api_key):
        return NOT_FOUND

    try:
        body = await request.json()
        targets = body.get("targets", {})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(targets, dict) or not targets:
        raise HTTPException(status_code=400, detail="Provide {\"targets\": {\"name\": \"ip\", ...}}")

    if len(targets) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 ping targets per request")

    tasks = [_ping_one(name, ip) for name, ip in targets.items()]
    results = await asyncio.gather(*tasks)

    return {"pings": results}
