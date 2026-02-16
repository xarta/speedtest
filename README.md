# speedtest-api

A Dockerised FastAPI service providing API-key-protected file upload/download
with SHA-256 checksum verification, designed for measuring connection speed and
reliability to a VPS. Includes a zero-dependency Python client.

## ⚠️ AI-Generated Content Notice

This project was **generated with AI assistance** and should be treated accordingly:

- **Not production-ready**: Created for a specific homelab environment.
- **May contain bugs**: AI-generated code can have subtle issues.
- **Author's Python experience**: The author is not an experienced Python programmer.

### AI Tools Used

- GitHub Copilot (Claude models)

### Licensing Note

Released under the **MIT License**. Given the AI-generated nature:

- The author makes no claims about originality
- Use at your own risk
- If you discover any copyright concerns, please open an issue

## Features

- **API-key authentication** — every endpoint returns `404` without a valid key (no information leakage)
- **Streaming upload** with SHA-256 checksum on both ends
- **1 GB max file size** enforced server-side
- **Constant-time key comparison** (`secrets.compare_digest`) to prevent timing attacks
- **Non-root container** — runs as `appuser` (uid 999)
- **Whoami** — shows your outgoing IP, reverse DNS, and server DNS
- **Ping** — server pings client-supplied targets in parallel (e.g. ISP gateways)
- **TLS certificate check** — client verifies cert validity and days until expiry
- **Security audit** — client probes all endpoints without a key to confirm they return 404
- **Zero-dependency client** — pure Python 3.12+ stdlib, downloadable from the server itself

## Prerequisites

- Docker & Docker Compose
- A reverse proxy providing TLS termination (the compose file includes [Traefik](https://traefik.io/) labels)
- A DNS record pointing your chosen domain at the host

## Quick Start

### 1. Configure

```bash
cp .env.example .env
# Edit .env — set your API key, domain, and data directory
```

See [.env.example](.env.example) for all available variables.

### 2. Deploy

```bash
docker compose up -d --build
```

### 3. Verify

```bash
# Should return 404 (no API key)
curl -s https://your-domain.example.com/

# Should return 404 (invalid key)
curl -s -H "X-API-Key: wrong" https://your-domain.example.com/api/list
```

## Client Usage

The client script is a single Python file with **zero external dependencies**.

Download it from the running server:

```bash
curl -H "X-API-Key: $SPEEDTEST_API_KEY" "$SPEEDTEST_URL/api/client" -o speedtest_client.py
```

Or copy it from the `client/` directory in this repo.

See [client/speedtest_client.usage.md](client/speedtest_client.usage.md) for
full command reference and examples.

## Project Structure

```
speedtest/
├── app/
│   ├── main.py              # FastAPI server — all endpoints
│   └── requirements.txt     # Python dependencies
├── client/
│   ├── speedtest_client.py  # CLI client (stdlib only)
│   └── speedtest_client.usage.md
├── compose.yaml             # Docker Compose with Traefik labels
├── Dockerfile               # Python 3.12-slim + non-root user
├── .env.example             # Template — copy to .env
├── .gitignore
└── README.md
```

## API Endpoints

All endpoints return `404` without a valid `X-API-Key` header.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/upload` | Stream upload (body = raw bytes, `X-Filename` header) |
| POST | `/api/upload-multipart` | Multipart form upload |
| GET | `/api/download/{filename}` | Download file (SHA-256 in `X-SHA256` response header) |
| GET | `/api/checksum/{filename}` | Get SHA-256 and size |
| GET | `/api/list` | List stored files |
| DELETE | `/api/delete/{filename}` | Delete a file |
| GET | `/api/client` | Download the client script |
| GET | `/api/whoami` | Client IP, reverse DNS, server DNS |
| POST | `/api/ping` | Ping targets (JSON body, max 10) |

## Environment Variables

All configuration is via environment variables — see [.env.example](.env.example).

Server variables are injected into the container via `compose.yaml`.
Client variables are set in your shell before running `speedtest_client.py`.

## License

MIT — see [LICENSE](LICENSE).
