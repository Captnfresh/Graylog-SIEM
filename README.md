# OmniLog — AI-Powered SIEM (Graylog + Claude)

A full-stack Security Information and Event Management (SIEM) platform with an AI-powered chat interface. Ask questions about your security logs in plain English and get real-time threat analysis powered by Claude AI.

---

## What's in this repo

| Service | Description | Port |
|---|---|---|
| **Graylog** | SIEM — log ingestion, search, dashboards, alerts | 9000 |
| **OpenSearch** | Log storage and indexing engine | 9200 |
| **MongoDB** | Graylog configuration store | — |
| **Backend (FastAPI)** | Bridges Graylog ↔ Claude AI | 8000 |
| **Frontend (React)** | OmniLog chat UI | 3000 |
| **Log Simulator** | Fires realistic SSH/security events into Graylog | — |

---

## Getting Started — Clone and Run Locally

### Prerequisites

Make sure you have the following installed before starting:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- [Git](https://git-scm.com/downloads)
- Windows users: WSL 2 enabled (Docker Desktop installs this automatically)

Verify Docker is working:

```bash
docker compose version
```

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/Captnfresh/Greylog-SIEM.git
cd Greylog-SIEM
```

---

### Step 2 — Set the WSL memory setting (Windows only, required for OpenSearch)

OpenSearch needs a Linux kernel setting to run. Run this once each time you restart your PC:

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

> **Mac/Linux users:** Run `sudo sysctl -w vm.max_map_count=262144` instead.

---

### Step 3 — Create your local `.env` file

The `.env` file holds secrets and is **never committed to GitHub**. You need to create it locally.

**Copy the example file:**

```bash
# Windows CMD
copy .env.example .env

# Mac / Linux / Git Bash
cp .env.example .env
```

**Generate a Graylog password secret** (required — must be at least 64 characters):

```bash
docker run --rm alpine sh -c "cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 96; echo"
```

Copy the output and paste it as `GRAYLOG_PASSWORD_SECRET` in your `.env`.

**Generate a SHA-256 hash of your chosen admin password:**

```bash
# Replace MyPassword123 with your chosen password
docker run --rm python:3.12-alpine python -c "import hashlib; print(hashlib.sha256(b'MyPassword123').hexdigest())"
```

Copy the output and paste it as `GRAYLOG_ROOT_PASSWORD_SHA2` in your `.env`.

**Fill in the remaining values** — your `.env` should look like this when done:

```env
# --- Graylog ---
GRAYLOG_PASSWORD_SECRET=<96-char string you generated>
GRAYLOG_ROOT_PASSWORD_SHA2=<sha256 hash you generated>
GRAYLOG_HTTP_EXTERNAL_URI=http://localhost:9000/

# Plain-text version of your admin password (used by the backend API)
GRAYLOG_ROOT_PASSWORD=MyPassword123

# --- Claude / Anthropic ---
# Get your key from: https://console.anthropic.com
# Team lead will share this on WhatsApp
ANTHROPIC_API_KEY=sk-ant-...

# --- SMTP Email (optional — for alert notifications) ---
SMTP_ENABLED=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_AUTH=true
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_USERNAME=your@gmail.com
SMTP_PASSWORD=your_app_password_here
SMTP_FROM_EMAIL=your@gmail.com
```

> **Note:** `GRAYLOG_ROOT_PASSWORD` must be the plain-text version of the same password you hashed for `GRAYLOG_ROOT_PASSWORD_SHA2`. The backend uses it to query the Graylog REST API.

---

### Step 4 — Start the full stack

```bash
docker compose up -d --build
```

This will build and start all 6 services. First run takes 3–5 minutes to download images and build containers.

Check everything is running:

```bash
docker compose ps
```

All services should show `Up` or `Up (healthy)`.

---

### Step 5 — Access the apps

| App | URL | Credentials |
|---|---|---|
| **OmniLog UI** | http://localhost:3000 | — |
| **Graylog Web UI** | http://localhost:9000 | admin / your password |
| **Backend API docs** | http://localhost:8000/docs | — |

---

### Step 6 — Install the SSH-SIEM Content Pack (optional but recommended)

The content pack adds pre-built SSH dashboards, streams, and alert rules to Graylog.

1. Go to **http://localhost:9000** and log in
2. Navigate to **System → Content Packs**
3. Click **Upload**
4. Upload the file: `content-pack-45312c4b-bc4d-4cf5-8799-b380c14aae09-1.json`
5. When prompted for `graylog_host`, enter your machine's local IP address (e.g. `192.168.1.x`) — not `localhost`
6. Click **Install**

---

### Step 7 — Try OmniLog

Open **http://localhost:3000** and try asking:

- *"Show failed login attempts"*
- *"Any suspicious network activity?"*
- *"What happened in the last 10 minutes?"*
- *"Are there any brute force attacks?"*

The log simulator runs automatically and sends realistic security events every 8 seconds. A coordinated attack scenario (brute force → port scan → SQL injection → data exfil) fires **once per hour** automatically so you can see the risk score spike and watch Claude analyse a real incident.

---

## Architecture

```
Log Simulator
     │ GELF UDP
     ▼
 Graylog :9000  ←──────────────────────────┐
     │                                      │
     │ REST API                             │
     ▼                                      │
FastAPI Backend :8000                       │
     │                                      │
     │ Claude API (Anthropic)               │
     ▼                                      │
 Claude claude-sonnet-4-6                          │
     │                                      │
     ▼                                      │
React Frontend :3000 ──── nginx proxy ─────┘
```

---

## Troubleshooting

### OpenSearch keeps restarting
Run the WSL memory command from Step 2 and restart the stack:
```bash
docker compose restart opensearch
```

### Graylog shows "DISCONNECTED" in OmniLog
Wait 60 seconds for Graylog to fully start — it takes longer than the other services. Check status with:
```bash
docker logs graylog --tail 20
```

### OmniLog shows "Rule-based mode" instead of Claude analysis
Your `ANTHROPIC_API_KEY` is missing or has no credits. The app still works with rule-based analysis — add credits at [console.anthropic.com](https://console.anthropic.com) to enable full Claude AI responses.

### Port conflicts
If port 3000 or 9000 is already in use, change the host-side port in `docker-compose.yml`:
```yaml
ports:
  - "3001:80"   # change 3000 to any free port
```

### Stopping the stack
```bash
docker compose down
```

To also delete all stored logs and data (full reset):
```bash
docker compose down -v
```

---

## Project Background

This project was built for the **Cyber Security Automation module** as a prototype SIEM with AI-assisted threat analysis.

**Stack:** Graylog 6.1 · OpenSearch 2.15 · MongoDB 7 · FastAPI · Claude claude-sonnet-4-6 · React 18 · TypeScript · Docker Compose

**Vendor:** Dumanyie Chamberlain — [github.com/D-rank-developer](https://github.com/D-rank-developer)
