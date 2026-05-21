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

## Getting Started — Team Setup Guide

> **You will need two things before starting — ask the team lead on WhatsApp:**
> 1. The **Anthropic API key** (`sk-ant-...`)
> 2. The shared **admin password** the team is using (e.g. `Admin@12345`)

---

### Before you begin — install these two things

| Tool | What it is | Download |
|---|---|---|
| **Docker Desktop** | Runs all the app services | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| **Git** | Downloads the code from GitHub | [git-scm.com/downloads](https://git-scm.com/downloads) |

Once installed, **restart your PC**, then open **Command Prompt** (Windows) or **Terminal** (Mac) and confirm Docker is working:

```bash
docker compose version
```

You should see a version number. If you get an error, make sure Docker Desktop is open and running in the background.

---

### Step 1 — Clone the repository

This downloads the project to your PC. Run this in Command Prompt / Terminal:

```bash
git clone https://github.com/Captnfresh/Greylog-SIEM.git
```

Then move into the project folder:

```bash
cd Greylog-SIEM
```

---

### Step 2 — Switch to the project branch

The main work lives on a specific branch. Switch to it with:

```bash
git checkout claude/reverent-vaughan
```

You should see:

```
Switched to branch 'claude/reverent-vaughan'
```

---

### Step 3 — One-time memory fix (Windows only)

OpenSearch needs a small system setting to run on Windows. Run this once — you'll need to repeat it each time you restart your PC:

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

> **Mac users:** Run `sudo sysctl -w vm.max_map_count=262144` instead.

---

### Step 4 — Create your `.env` file

The `.env` file contains passwords and API keys. It is **never uploaded to GitHub** — everyone creates their own copy locally.

**4a — Copy the template:**

```bash
# Windows CMD
copy .env.example .env

# Mac / Git Bash
cp .env.example .env
```

**4b — Generate a secret key for Graylog** (paste the result into `.env` as `GRAYLOG_PASSWORD_SECRET`):

```bash
docker run --rm alpine sh -c "cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 96; echo"
```

**4c — Generate a password hash** — replace `Admin@12345` below with whatever password the team lead shared:

```bash
docker run --rm python:3.12-alpine python -c "import hashlib; print(hashlib.sha256(b'Admin@12345').hexdigest())"
```

Paste the output as `GRAYLOG_ROOT_PASSWORD_SHA2` in your `.env`.

**4d — Open `.env` in Notepad and fill in the blanks.** It should look like this when done:

```env
GRAYLOG_PASSWORD_SECRET=<output from step 4b>
GRAYLOG_ROOT_PASSWORD_SHA2=<output from step 4c>
GRAYLOG_HTTP_EXTERNAL_URI=http://localhost:9000/
GRAYLOG_ROOT_PASSWORD=Admin@12345
ANTHROPIC_API_KEY=<API key from team lead>
SMTP_ENABLED=false
```

> Leave all the `SMTP_` lines as-is — email alerts are disabled by default.

---

### Step 5 — Launch Environment 1: Graylog SIEM Stack

This starts Graylog, OpenSearch, MongoDB, the AI backend, and the log simulator — all at once:

```bash
docker compose up -d --build
```

The **first run** takes 3–5 minutes to download and build everything. Subsequent starts are much faster.

Once it finishes, check everything is running:

```bash
docker compose ps
```

You should see 5 containers all showing **Up**:

```
graylog                Up (healthy)
graylog-mongodb        Up
graylog-opensearch     Up
omnilog-backend        Up
omnilog-log-simulator  Up
```

> **Graylog takes about 60 seconds to fully start** after the containers show Up — this is normal. Wait a moment before opening the UI.

---

### Step 6 — Launch Environment 2: OmniLog Chat UI

Open a **second** Command Prompt / Terminal window, make sure you are still in the `Greylog-SIEM` folder, then run:

```bash
cd frontend
npm install
npm run dev
```

> **First time only:** `npm install` downloads the UI dependencies — takes ~1 minute.

You should see:

```
  VITE v5.x.x  ready in ...ms
  ➜  Local:   http://localhost:8080/
```

---

### Step 7 — Open the apps

You now have two environments running. Open these in your browser:

| What | URL | Login |
|---|---|---|
| 🤖 **OmniLog AI Chat** | http://localhost:8080 | No login needed |
| 📊 **Graylog Dashboard** | http://localhost:9000 | `admin` / your password |

The top-right corner of OmniLog should show **CONNECTED** in green. The sidebar will start showing live security event counts within a few seconds.

---

### Step 8 — Try it out

In the OmniLog chat box, try asking:

- *"Show failed login attempts"*
- *"Any suspicious network activity?"*
- *"What happened in the last 10 minutes?"*
- *"Are there any brute force attacks?"*

The log simulator runs in the background automatically — it sends realistic SSH and network security events every 8 seconds. Once per hour it runs a full coordinated attack scenario (brute force → port scan → SQL injection → data exfiltration) so you can see the risk score spike and watch the AI analyse a live incident.

---

### Stopping everything

When you're done, stop the SIEM stack with:

```bash
docker compose down
```

And press `Ctrl + C` in the terminal running the frontend to stop it.

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
