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

✅ What Docker Compose did for us:
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
