#!/usr/bin/env python3
"""
Speedtest Client - Upload/download files with checksum verification.

Usage:
    python speedtest_client.py upload   myfile.bin
    python speedtest_client.py download myfile.bin
    python speedtest_client.py download myfile.bin -o /tmp/myfile.bin
    python speedtest_client.py checksum myfile.bin
    python speedtest_client.py list
    python speedtest_client.py delete   myfile.bin
    python speedtest_client.py generate 100M
    python speedtest_client.py generate 1G
    python speedtest_client.py check

Environment variables (see .env.example):
    SPEEDTEST_API_KEY   - required, the API key for authentication
    SPEEDTEST_URL       - required, base URL of the speedtest server (e.g. https://speedtest.example.com)
    SPEEDTEST_PING_TARGETS - optional, comma-separated name=ip pairs for ping checks
                             (e.g. "MyISP=1.2.3.4,OtherISP=5.6.7.8")

All env vars can also be passed as --key, --url, --ping-targets command-line args.
"""

import argparse
import hashlib
import json
import os
import ssl
import socket
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB
CHECK_TIMEOUT = 10  # seconds - overall timeout for check operations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def format_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.2f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.2f} TB"


def format_speed(nbytes: int, seconds: float) -> str:
    if seconds == 0:
        return "N/A"
    bits = nbytes * 8
    mbps = bits / seconds / 1_000_000
    return f"{mbps:.2f} Mbps"


def _api_call(url: str, headers: dict | None = None, method: str = "GET",
              data: bytes | None = None, timeout: int = 10) -> tuple[int, bytes, dict]:
    """Make an HTTP request returning (status_code, body, response_headers)."""
    hdrs = headers or {}
    req = Request(url, headers=hdrs, method=method, data=data)
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            rh = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, rh
    except HTTPError as e:
        body = e.read()
        return e.code, body, {}
    except (URLError, OSError) as e:
        return 0, str(e).encode(), {}


def _parse_ping_targets(raw: str) -> dict[str, str]:
    """Parse 'Name1=IP1,Name2=IP2' into a dict."""
    targets = {}
    if not raw.strip():
        return targets
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            name, ip = pair.split("=", 1)
            targets[name.strip()] = ip.strip()
    return targets


# ---------------------------------------------------------------------------
# Upload / Download (timing-sensitive - no extra work mixed in)
# ---------------------------------------------------------------------------

def do_upload(base_url: str, api_key: str, filepath: str):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    print(f"Uploading: {filename} ({format_size(filesize)})")

    local_sha = sha256_file(filepath)
    print(f"Local SHA-256: {local_sha}")

    with open(filepath, "rb") as f:
        data = f.read()

    req = Request(
        f"{base_url}/api/upload",
        data=data,
        method="POST",
        headers={
            "X-API-Key": api_key,
            "X-Filename": filename,
            "Content-Type": "application/octet-stream",
        },
    )

    t0 = time.time()
    try:
        with urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read())
    except HTTPError as e:
        if e.code == 404:
            print("ERROR: 404 - Invalid API key or endpoint not found.", file=sys.stderr)
        else:
            print(f"ERROR: HTTP {e.code} - {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.time() - t0

    remote_sha = result.get("sha256", "")
    print(f"Remote SHA-256: {remote_sha}")
    if local_sha == remote_sha:
        print("Checksum MATCH")
    else:
        print("Checksum MISMATCH!", file=sys.stderr)
        sys.exit(1)

    print(f"Upload speed: {format_speed(filesize, elapsed)} ({elapsed:.1f}s)")


def do_download(base_url: str, api_key: str, filename: str, output: str | None):
    dest = output or filename
    print(f"Downloading: {filename} -> {dest}")

    req = Request(
        f"{base_url}/api/download/{filename}",
        headers={"X-API-Key": api_key},
    )

    t0 = time.time()
    try:
        with urlopen(req, timeout=600) as resp:
            remote_sha = resp.headers.get("X-SHA256", "")
            total = 0
            h = hashlib.sha256()
            with open(dest, "wb") as f:
                while chunk := resp.read(CHUNK_SIZE):
                    f.write(chunk)
                    h.update(chunk)
                    total += len(chunk)
    except HTTPError as e:
        if e.code == 404:
            print("ERROR: 404 - Invalid API key or file not found.", file=sys.stderr)
        else:
            print(f"ERROR: HTTP {e.code} - {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.time() - t0

    local_sha = h.hexdigest()
    print(f"Remote SHA-256: {remote_sha}")
    print(f"Local SHA-256:  {local_sha}")
    if remote_sha and local_sha == remote_sha:
        print("Checksum MATCH")
    elif not remote_sha:
        print("WARNING: No remote checksum provided")
    else:
        print("Checksum MISMATCH!", file=sys.stderr)
        sys.exit(1)

    print(f"Downloaded: {format_size(total)}")
    print(f"Download speed: {format_speed(total, elapsed)} ({elapsed:.1f}s)")


# ---------------------------------------------------------------------------
# Simple commands
# ---------------------------------------------------------------------------

def do_checksum(base_url: str, api_key: str, filename: str):
    status, body, _ = _api_call(f"{base_url}/api/checksum/{filename}", {"X-API-Key": api_key})
    if status != 200:
        print(f"ERROR: HTTP {status}", file=sys.stderr)
        sys.exit(1)
    result = json.loads(body)
    print(f"File:   {result['filename']}")
    print(f"Size:   {format_size(result['size'])}")
    print(f"SHA256: {result['sha256']}")


def do_list(base_url: str, api_key: str):
    status, body, _ = _api_call(f"{base_url}/api/list", {"X-API-Key": api_key})
    if status != 200:
        print(f"ERROR: HTTP {status}", file=sys.stderr)
        sys.exit(1)
    files = json.loads(body).get("files", [])
    if not files:
        print("No files stored.")
        return
    for f in files:
        print(f"  {f['filename']:40s} {format_size(f['size']):>12s}")


def do_delete(base_url: str, api_key: str, filename: str):
    status, body, _ = _api_call(f"{base_url}/api/delete/{filename}", {"X-API-Key": api_key}, method="DELETE")
    if status != 200:
        print(f"ERROR: HTTP {status}", file=sys.stderr)
        sys.exit(1)
    result = json.loads(body)
    print(f"Deleted: {result['deleted']}")


def parse_size(s: str) -> int:
    s = s.upper().strip()
    multipliers = {"B": 1, "K": 1024, "KB": 1024, "M": 1024**2, "MB": 1024**2, "G": 1024**3, "GB": 1024**3}
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * mult)
    return int(s)


def do_generate(base_url: str, api_key: str, size_str: str):
    nbytes = parse_size(size_str)
    if nbytes > 1024**3:
        print("ERROR: Maximum size is 1 GB", file=sys.stderr)
        sys.exit(1)

    print(f"Generating {format_size(nbytes)} of random data...")
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        remaining = nbytes
        while remaining > 0:
            chunk = min(CHUNK_SIZE, remaining)
            tmp.write(os.urandom(chunk))
            remaining -= chunk
        tmpname = tmp.name

    try:
        do_upload(base_url, api_key, tmpname)
    finally:
        os.unlink(tmpname)


# ---------------------------------------------------------------------------
# CHECK command - security audit, cert check, whoami, ping
# ---------------------------------------------------------------------------

def _check_certificate(hostname: str) -> dict:
    """Check TLS certificate validity and expiry."""
    result = {"hostname": hostname, "valid": False}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(CHECK_TIMEOUT)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        san = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

        result.update({
            "valid": now >= not_before and now <= not_after,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
            "subject_cn": subject.get("commonName", "unknown"),
            "san": san,
            "not_before": not_before_str,
            "not_after": not_after_str,
            "days_remaining": days_remaining,
            "expired": days_remaining < 0,
            "expiring_soon": 0 <= days_remaining <= 14,
        })
    except Exception as e:
        result["error"] = str(e)

    return result


def _check_security(base_url: str) -> list[dict]:
    """Probe all known API endpoints WITHOUT a key - all should return 404."""
    endpoints = [
        ("GET",    "/"),
        ("GET",    "/api/list"),
        ("GET",    "/api/download/test.bin"),
        ("GET",    "/api/checksum/test.bin"),
        ("GET",    "/api/client"),
        ("GET",    "/api/whoami"),
        ("POST",   "/api/ping"),
        ("POST",   "/api/upload"),
        ("POST",   "/api/upload-multipart"),
        ("DELETE", "/api/delete/test.bin"),
        ("GET",    "/admin"),
        ("GET",    "/docs"),
        ("GET",    "/openapi.json"),
        ("GET",    "/redoc"),
    ]
    results = []
    for method, path in endpoints:
        try:
            hdrs = {}
            post_data = None
            if method == "POST":
                post_data = b""
                hdrs["Content-Length"] = "0"
            status, _, _ = _api_call(f"{base_url}{path}", headers=hdrs,
                                     method=method, data=post_data, timeout=CHECK_TIMEOUT)
        except Exception:
            status = 0
        ok = status == 404
        results.append({"method": method, "path": path, "status": status, "secure": ok})
    return results


def do_check(base_url: str, api_key: str, ping_targets: dict[str, str]):
    """Run all checks: security, certificate, whoami, ping."""
    from urllib.parse import urlparse
    hostname = urlparse(base_url).hostname or "localhost"
    all_ok = True

    # --- 1. Certificate Check ---
    print("=" * 60)
    print("CERTIFICATE CHECK")
    print("=" * 60)
    cert = _check_certificate(hostname)
    if cert.get("error"):
        print(f"  ERROR: {cert['error']}")
        all_ok = False
    else:
        status_icon = "OK" if cert["valid"] and not cert.get("expiring_soon") else "WARNING" if cert.get("expiring_soon") else "FAIL"
        print(f"  Status:     {status_icon}")
        print(f"  Issuer:     {cert.get('issuer', 'unknown')}")
        print(f"  Subject:    {cert.get('subject_cn', 'unknown')}")
        print(f"  SANs:       {', '.join(cert.get('san', []))}")
        print(f"  Valid from: {cert.get('not_before', '?')}")
        print(f"  Expires:    {cert.get('not_after', '?')}")
        print(f"  Days left:  {cert.get('days_remaining', '?')}")
        if cert.get("expired"):
            print("  ** CERTIFICATE IS EXPIRED! **")
            all_ok = False
        elif cert.get("expiring_soon"):
            print("  ** CERTIFICATE EXPIRING WITHIN 14 DAYS **")

    # --- 2. Security Check (no key) ---
    print()
    print("=" * 60)
    print("SECURITY CHECK (probing without API key)")
    print("=" * 60)
    sec_results = _check_security(base_url)
    leak_count = 0
    for r in sec_results:
        icon = "OK" if r["secure"] else "LEAK!"
        line = f"  [{icon:5s}] {r['method']:6s} {r['path']:30s} -> {r['status']}"
        print(line)
        if not r["secure"]:
            leak_count += 1
    if leak_count == 0:
        print("  All endpoints properly return 404 without API key.")
    else:
        print(f"  ** {leak_count} ENDPOINT(S) LEAKING DATA WITHOUT API KEY! **")
        all_ok = False

    # --- 3. Whoami (with key) ---
    print()
    print("=" * 60)
    print("CLIENT NETWORK INFO (whoami)")
    print("=" * 60)
    status, body, _ = _api_call(f"{base_url}/api/whoami", {"X-API-Key": api_key}, timeout=CHECK_TIMEOUT)
    if status == 200:
        info = json.loads(body)
        print(f"  Your IP:      {info.get('client_ip', 'unknown')}")
        rdns = info.get("reverse_dns")
        if rdns:
            print(f"  Reverse DNS:  {rdns}")
        server_dns = info.get("server_dns_lookup")
        if server_dns:
            print(f"  Server IPs:   {', '.join(server_dns)}")
        domain = info.get("server_domain")
        if domain:
            print(f"  Server domain: {domain}")
        xff = info.get("x_forwarded_for")
        if xff:
            print(f"  X-Fwd-For:    {xff}")
        xri = info.get("x_real_ip")
        if xri:
            print(f"  X-Real-IP:    {xri}")
    else:
        print(f"  ERROR: HTTP {status}")
        all_ok = False

    # --- 4. Ping (with key, targets from client) ---
    print()
    print("=" * 60)
    print("PING CHECK (server-side)")
    print("=" * 60)
    if not ping_targets:
        print("  No ping targets configured (set SPEEDTEST_PING_TARGETS).")
    else:
        payload = json.dumps({"targets": ping_targets}).encode()
        status, body, _ = _api_call(
            f"{base_url}/api/ping",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            method="POST",
            data=payload,
            timeout=CHECK_TIMEOUT,
        )
        if status == 200:
            pings = json.loads(body).get("pings", [])
            for p in pings:
                icon = "OK" if p.get("reachable") else "UNREACHABLE"
                print(f"  [{icon}] {p['name']:6s} ({p['ip']})")
                if p.get("rtt"):
                    print(f"           RTT: {p['rtt']}")
                if p.get("packet_loss"):
                    print(f"           {p['packet_loss']}")
                if p.get("detail"):
                    print(f"           Detail: {p['detail']}")
        else:
            print(f"  ERROR: HTTP {status}")

    # --- Summary ---
    print()
    print("=" * 60)
    if all_ok:
        print("ALL CHECKS PASSED")
    else:
        print("SOME CHECKS FAILED - see above")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Speedtest Client - upload/download with checksum verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--key", default=os.environ.get("SPEEDTEST_API_KEY", ""),
                        help="API key (or set SPEEDTEST_API_KEY env var)")
    parser.add_argument("--url", default=os.environ.get("SPEEDTEST_URL", ""),
                        help="Base URL (or set SPEEDTEST_URL env var)")
    parser.add_argument("--ping-targets", default=os.environ.get("SPEEDTEST_PING_TARGETS", ""),
                        help="Comma-separated Name=IP pairs (or set SPEEDTEST_PING_TARGETS)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_up = sub.add_parser("upload", help="Upload a file")
    p_up.add_argument("file", help="File to upload")

    p_down = sub.add_parser("download", help="Download a file")
    p_down.add_argument("filename", help="Remote filename")
    p_down.add_argument("-o", "--output", help="Output path (default: same as remote name)")

    p_cs = sub.add_parser("checksum", help="Get checksum of remote file")
    p_cs.add_argument("filename")

    sub.add_parser("list", help="List stored files")

    p_del = sub.add_parser("delete", help="Delete a remote file")
    p_del.add_argument("filename")

    p_gen = sub.add_parser("generate", help="Generate random data and upload")
    p_gen.add_argument("size", help="Size (e.g. 100M, 1G)")

    sub.add_parser("check", help="Security audit, cert check, IP info, ping targets")

    args = parser.parse_args()

    if not args.key:
        print("ERROR: API key required. Use --key or set SPEEDTEST_API_KEY.", file=sys.stderr)
        sys.exit(1)

    if not args.url:
        print("ERROR: Server URL required. Use --url or set SPEEDTEST_URL.", file=sys.stderr)
        sys.exit(1)

    match args.command:
        case "upload":
            do_upload(args.url, args.key, args.file)
        case "download":
            do_download(args.url, args.key, args.filename, args.output)
        case "checksum":
            do_checksum(args.url, args.key, args.filename)
        case "list":
            do_list(args.url, args.key)
        case "delete":
            do_delete(args.url, args.key, args.filename)
        case "generate":
            do_generate(args.url, args.key, args.size)
        case "check":
            targets = _parse_ping_targets(args.ping_targets)
            do_check(args.url, args.key, targets)


if __name__ == "__main__":
    main()
