Below is a **copy-paste README.md section** documenting everything we’ve done so far (Stage 1). It’s written so a non-technical reader can still follow the story, while technical teammates can reproduce the setup.

---

# Portfolio 01: Security Monitoring — Graylog SIEM (Docker Lab)

This repository contains our **Security Monitoring prototype** for the Cyber Security Automation module.

We are building a **centralised security monitoring solution** (SIEM) that can:
- collect logs from servers and systems,
- store and search them efficiently,
- present them in dashboards,
- detect suspicious activity (e.g., brute force logins),
- trigger alerts (email),
- generate automated reports.

---

## 1) What we are building (simple explanation)

### What is a SIEM?
A **SIEM** (Security Information and Event Management) is a platform that helps an organisation:
- **collect** security-relevant logs from many systems,
- **search and analyse** events quickly,
- **detect threats** using rules and correlation,
- **alert** security teams in real time,
- **report** on security activity for compliance.

### SIEM tools are not one thing
“SIEM” is a category of tools. Examples include:
- **Graylog**
- **Splunk**
- **Microsoft Sentinel**
- and others

In this project we chose **Graylog**.

---

## 2) Our Architecture (what runs where)

We deployed the SIEM using **Docker Compose**, which runs multiple services together.

### Components we deployed
- **Graylog** (`graylog/graylog:6.1`)
  - The SIEM “brain” + web interface:
  - dashboards, searches, alerts, correlation rules, reporting

- **OpenSearch** (`opensearchproject/opensearch:2.15.0`)
  - Where the *actual log messages/events* are stored and indexed
  - This is what makes searches and dashboards fast

- **MongoDB** (`mongo:7`)
  - Stores Graylog **configuration**, not the raw logs
  - Examples: users, inputs, dashboards, streams, alert rules

### How data flows (high level)
Systems in an environment generate logs (Linux servers, Windows, firewalls, apps).  
Those logs are forwarded into Graylog inputs, then stored/indexed in OpenSearch.

**Log sources → Graylog Inputs → OpenSearch storage/index → Graylog search/dashboards/alerts**

---

## 3) Current Status (Where we are in the project)

✅ **Stage 1 COMPLETE: SIEM deployment is healthy**
- Graylog, OpenSearch, and MongoDB containers are running
- Graylog web interface is accessible locally:
  - `http://127.0.0.1:9000`

This corresponds to the early part of the project timeline: **provisioning and base architecture**.

---

## 4) Why Docker Compose?
Instead of running multiple containers one-by-one, Docker Compose lets us define everything in one file and start it with one command.

### What Docker Compose did for us:
- pulled required images automatically (if not present),
- created containers from those images,
- created a private Docker network so services can talk to each other,
- applied ports/volumes/environment settings.

---

## 5) Step-by-step: What we did (Stage 1)

> Notes:
> - We performed this setup on **Windows (Command Prompt)**.
> - Folder used: `C:\Users\PC\graylog-lab`

### Step 1 — Create a project folder
We created a workspace folder to keep all files organised:

- `docker-compose.yml`
- `.env` (local secrets)
- `.gitignore`
- `.env.example`
- `README.md`

### Step 2 — Create a Graylog secret (required)
Graylog requires a long random secret to secure internal values like sessions.

We generated a 96-character alphanumeric secret using Docker:

```cmd
docker run --rm alpine sh -c "cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 96; echo"
````

This secret was stored in `.env` as:

* `GRAYLOG_PASSWORD_SECRET=...`

### Step 3 — Create an admin password hash (required)

Graylog expects the admin password in **SHA-256 hashed form** (not plain text).

We chose an admin password and generated its SHA-256 hash using Docker:

```cmd
docker run --rm python:3.12-alpine python -c "import hashlib; print(hashlib.sha256(b'Admin@12345').hexdigest())"
```

Stored in `.env` as:

* `GRAYLOG_ROOT_PASSWORD_SHA2=...`

### Step 4 — Create `.env` (local configuration)

We created `.env` locally (NOT pushed to GitHub) containing:

* `GRAYLOG_PASSWORD_SECRET=...`
* `GRAYLOG_ROOT_PASSWORD_SHA2=...`
* `GRAYLOG_HTTP_EXTERNAL_URI=http://127.0.0.1:9000/`

### Step 5 — Create `docker-compose.yml`

We created a Docker Compose stack defining 3 services:

* `mongodb`
* `opensearch`
* `graylog`

This enabled the full SIEM stack to start with one command:

```cmd
docker compose up -d
```

### Step 6 — Required OpenSearch system setting (vm.max_map_count)

OpenSearch requires a Linux kernel setting called `vm.max_map_count` to run reliably.

On Windows (Docker Desktop), we set it in the Docker WSL environment:

```cmd
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

### Step 7 — Start the stack

We started the environment:

```cmd
docker compose up -d
docker compose ps
```

Graylog UI became reachable at:

* `http://127.0.0.1:9000`

---

## 6) Problems we faced (and how we fixed them)

These are the real troubleshooting lessons learned during deployment.

### Issue A — Commands didn’t work in CMD

Some commands shown online are PowerShell-specific. We were using **Command Prompt**, so the `$variable` syntax failed.

### Fix:
We used Docker commands to generate secrets/hashes instead.

---

### Issue B — OpenSearch kept restarting

OpenSearch showed:

* `Restarting (1)`

Logs said OpenSearch needed an initial admin password (OpenSearch security requirement).

### Fix:
We added an environment variable in `docker-compose.yml` under OpenSearch:

* `OPENSEARCH_INITIAL_ADMIN_PASSWORD=OpenSearch@12345!`

After that, OpenSearch stayed **Up**.

---

### Issue C — Graylog login failed (first run)

On first run, Graylog started an **initial setup interface** and generated a temporary admin password.

### Fix:
We checked Graylog logs and used the temporary credentials shown there to complete initial setup.

---

### Issue D — Graylog stayed “unhealthy” and couldn’t reach OpenSearch

Graylog logs repeatedly showed it was trying to connect to:

* `127.0.0.1:9200` (connection refused)

Inside Docker, `127.0.0.1` means “this container itself”, not OpenSearch.

### Fix:
We ensured Graylog points to OpenSearch using the Docker service name:

* `http://opensearch:9200`

And we added the compatibility environment variable (this was the key final fix):

* `GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200`

After recreating Graylog container, status became:
  `Up (healthy)`

---

## 7) How this works in an organisation (enterprise view)

### Where are logs in a real environment?

Logs are generated **on each system** (locally):

* Linux: `/var/log/...`
* Windows: Event Viewer / Windows Event Logs
* Firewalls: device logs
* Cloud: service audit logs (Azure/AWS)

Those logs are then **forwarded across the organisation network** into the SIEM.

### Does the SIEM sit “on the network”?

The SIEM is usually deployed in a secured internal segment (SOC network / monitoring zone).
Log sources send logs to the SIEM over internal networks (often with segmentation + firewall rules).

In enterprise environments:

* logs are forwarded securely (often using TLS),
* systems are segmented (VLANs / firewalls),
* uptime, backups, and scaling are planned.

This lab is a prototype, but the **concept is the same**.

---

## 8) Team workflow (roles + GitHub approach)

We are doing group work but the assessment is individual, so everyone must be involved.

### Recommended workflow

* We maintain one **central repo** (this repo).
* Each person works on their own **branch**:

  * `feature/log-collection`
  * `feature/dashboards`
  * `feature/alerts`
  * `feature/reporting`
* Changes are merged into `main` after review.

### Important note about SIEM UI changes

Some work done inside the Graylog web UI (dashboards, alerts, streams) is stored in MongoDB volumes locally.
To share that work via GitHub, we will:

* export configurations where possible (JSON/content packs), and/or
* document exact steps clearly in `/docs/`.

---

## 9) How everyone of us can run this on our Local PC

### Prerequisites

* Docker Desktop installed
* Docker Compose available (`docker compose version`)
* Windows users: ensure WSL command works (for vm.max_map_count)

### Clone

```bash
git clone https://github.com/Captnfresh/Greylog-SIEM.git
cd Greylog-SIEM
```

### Create your local `.env`

We do NOT store `.env` in GitHub. Create it locally.

Copy the example file:

```bash
# Windows CMD
copy .env.example .env
```

Then edit `.env` and set:

* `GRAYLOG_PASSWORD_SECRET`
* `GRAYLOG_ROOT_PASSWORD_SHA2`

(I'll share these values with the team on whatsapp)

### Set vm.max_map_count (required for OpenSearch)

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

### Start

```bash
docker compose up -d
docker compose ps
```

### Access Graylog

* `http://127.0.0.1:9000`

---

## 10) What’s next (The next steps)

### Stage 2 — Log Ingestion

* Create Graylog inputs (Syslog / GELF)
* Send logs from a test source (Linux/auth logs)
* Confirm messages arrive in Search

### Stage 3 — Parsing + Normalisation

* Extract fields (IP, username, status, action)
* Create consistent searchable fields

### Stage 4 — Dashboards

* Build demo dashboards:

  * Security Overview Dashboard
  * Game Server Health Dashboard
* Expand to 5 key dashboards (requirement)

### Stage 5 — Correlation Rules + Alerting

* Detect brute force login attempts
* Generate an alert
* Send automated email notification

### Stage 6 — Automated Reporting (Python)

* Build a script to generate daily/weekly summary report
* Show the script in demo

### Stage 7 — Testing + Documentation + Demo Prep

* Basic performance checks (prototype level)
* Troubleshooting notes
* Training materials
* Final demo script and walkthrough

```

