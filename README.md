# speedtest-api

A Dockerised FastAPI service providing API-key-protected file upload/download
with SHA-256 checksum verification, designed for measuring connection speed and
reliability to a VPS. Includes a zero-dependency Python client.

## Background

I'm setting up my OpenClaw and IronClaw instances in hardened VM's on my main Proxmox instance.  I don't want to give the agents in this VM my key secrets and prefer it not to know my residential ISP addresses and so I'm adding proxies and brokers and whatnot *OUTSIDE* of the VM and route it's outgoing internet via a vlan and one of my pfsense VM's to use a NordVPN client I have setup on there.  This way I can take measures to guard against DNS leaks and the like.  I also drop any outgoing private range packets *except* to my proxies and brokers as required - via a Caddy reverse proxy for layer 7 url filtering.  e.g. to avoid some vulnerabilities ... e.g. vLLM had a vulnerability on its endpoints that wouldn't be exposed if only the completions endpoint was accessible.  Although I'm using liteLLM anyway with virtual keys to prevent key leakage if my OpenClaw et al are compromised, even to my local vLLM endpoints.  It leaves the door open for inserting some protection against prompt injection too.  Because I'm routing internet access via NordVPN it's useful to have a script to check network connectivity and since I have a VPS handy it makes sense to use that.  I developed these scripts in an hour or so - with some back and forth and testing and evolution etc.  Without Generative AI this would have taken me many hours and indeed was on my TODO list for years!  Hopefully it's secure(ish) lol.  :)  (I have reviewed it and can't see anything obvious).

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
