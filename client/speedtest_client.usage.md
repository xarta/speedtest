# Speedtest API - Usage Guide

## Setup

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your actual values
```

### Client environment

The client script reads configuration from environment variables.
Set them in your shell or in a local `.env` file:

```bash
export SPEEDTEST_API_KEY="your-api-key-here"
export SPEEDTEST_URL="https://speedtest.example.com"
export SPEEDTEST_PING_TARGETS="ISP1=1.2.3.4,ISP2=5.6.7.8"
```

The client script is pure Python 3.12+ with **zero dependencies** (stdlib only).

## Commands

### Check (security audit, cert, IP info, ping)
```bash
python speedtest_client.py check
```
This runs:
1. **Certificate check** - verifies TLS cert is valid and not near expiry
2. **Security audit** - probes all API endpoints without a key to confirm they return 404
3. **Whoami** - shows your outgoing IP address, reverse DNS, and server DNS records
4. **Ping** - server pings the targets defined in `SPEEDTEST_PING_TARGETS` in parallel

### Upload a file
```bash
python speedtest_client.py upload myfile.bin
```

### Generate random data and upload (speed test)
```bash
python speedtest_client.py generate 100M
python speedtest_client.py generate 1G
```

### Download a file
```bash
python speedtest_client.py download myfile.bin
python speedtest_client.py download myfile.bin -o /tmp/myfile.bin
```

### List stored files
```bash
python speedtest_client.py list
```

### Get checksum of a remote file
```bash
python speedtest_client.py checksum myfile.bin
```

### Delete a remote file
```bash
python speedtest_client.py delete myfile.bin
```

## Download the client from the server
```bash
curl -H "X-API-Key: $SPEEDTEST_API_KEY" "$SPEEDTEST_URL/api/client" -o speedtest_client.py
```

## Notes
- Maximum file size: **1 GB**
- All uploads/downloads are verified with **SHA-256 checksums**
- Without a valid API key, every endpoint returns **404** (no information leakage)
- Upload/download speed timings are isolated from other operations
- The `check` command has a **10 second** timeout per network call
- Ping targets are sent from the client to the server (max 10 per request)
