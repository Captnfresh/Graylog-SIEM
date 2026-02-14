# Graylog SIEM Lab — Log Ingestion, Parsing, Detection & Email Alerts 

This repository contains a reproducible Graylog SIEM lab built for security monitoring.
It covers:

* **Phase 1:** Log ingestion (inputs)
* **Phase 2:** Parsing & normalization (extractors → `source_ip`, `username`, `action`, `event_type`)
* **Phase 3:** Detection & alerting (stream + 8 event definitions + email notifications)
* **Phase 4 (Next):** Dashboards & visualisation (handover below)

> Goal: Any team member (or lecturer) should be able to clone the repo, bring up the lab, run bootstrap, forward SSH logs using rsyslog, and see **parsed fields + streams + alerts + email notifications** working with minimal overhead.

---

## Repository Structure (Important)

* `docker-compose.yml` → Graylog/MongoDB/OpenSearch + SMTP environment variables
* `.env.example` → template for required secrets/config
* `bootstrap.ps1` → recreates inputs + extractors (safe to re-run)
* `graylog-config/` → exported JSON for inputs & extractors
* `content-packs/` → exported content pack(s) for streams/event-definitions/notifications (Phase 3)

---

# Getting Started (Environment Setup)

## 1) Clone Repository

```bash
git clone https://github.com/Captnfresh/Graylog-SIEM.git
cd graylog-lab
git checkout feature/phase2-graylog-parsing
copy .env.example .env
```

---

## 2) Configure `.env`

Open `.env` and set the required values (shared internally with team).

Example keys used in this lab:

* `GRAYLOG_PASSWORD_SECRET`
* `GRAYLOG_ROOT_PASSWORD_SHA2`
* `GRAYLOG_HTTP_EXTERNAL_URI`
* `GRAYLOG_OPENSEARCH_HOSTS`

> Do **not** commit real passwords or app passwords to GitHub.

---

## 3) Start Environment (Docker)

```powershell
docker compose up -d
docker ps
```

Wait 1–2 minutes for Graylog to fully start.

---

## 4) Access Graylog UI

Open:

```
http://localhost:9000
```

Login (shared with team):

* Username: `admin`
* Password: *(team shared value)*

---

# Phase 1 & 2 — Inputs + Extractors (Bootstrap)

## 5) Run Bootstrap (Auto-Configuration)

Bootstrap recreates:

 Inputs
 Extractors attached to **syslog-tcp**

Run:

```powershell
.\bootstrap.ps1
```

Expected outcome inside Graylog UI:

* Inputs running:

  * `syslog-tcp` (1514)
  * `syslog-udp` (1514)
  * `gelf-udp` (12201)
* Extractors attached to **syslog-tcp**:

  * `extract_source_ip`
  * `extract_username`
  * `extract_action`
  * `extract_event_type`

---

## 6) Verify Parsing Works (Phase 2 success criteria)

After logs arrive via **syslog-tcp**, Graylog should show these normalized fields:

* `source_ip`
* `username`
* `action`
* `event_type`

> If these fields don’t appear, it usually means logs are arriving through **syslog-udp** instead of **syslog-tcp** (very common mistake).

---

# Preferred Log Testing Method — rsyslog (What We Used in Practice)

We forward **real SSH/auth logs** from Ubuntu/WSL → Graylog via **TCP syslog**.

## 7) On WSL Ubuntu: Install/enable ssh + rsyslog

```bash
sudo apt update
sudo apt install -y rsyslog openssh-server
sudo systemctl enable --now rsyslog
sudo systemctl enable --now ssh
```

---

## 8) Configure rsyslog forwarding to Graylog (TCP)

Create or edit:

```bash
sudo nano /etc/rsyslog.d/60-graylog.conf
```

Use the **modern TCP forwarding** config:

```conf
# Forward auth logs (SSH) to Graylog via TCP syslog
auth,authpriv.* action(
  type="omfwd"
  target="127.0.0.1"
  port="1514"
  protocol="tcp"
)
```

Restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

---

## 9) Generate SSH logs (to confirm end-to-end)

From **Windows PowerShell** or another terminal, SSH into WSL to generate real logs:

```powershell
ssh <wsl-username>@<wsl-ip>
```

To get WSL IP:

```bash
ip addr | grep inet
```

Then do a few wrong-password attempts to create “Failed password” entries.

---

## 10) Confirm logs + fields in Graylog

In Graylog UI:

* Search → Time range: Last 15 minutes
* Query:

```
event_type:sshd
```

Open a message and confirm fields exist:
 `event_type = sshd`
 `source_ip = <attacker ip>`
 `username = <attempted user>`
 `action = failed` (or accepted, depending on log)

---

# Phase 3 — Detection & Alerting (Stream + Alerts + Email)

## 11) SMTP Email Setup (docker-compose + env vars)

SMTP is configured through Graylog environment variables in `docker-compose.yml` (under `graylog: environment:`).

Example (Gmail + TLS 587):

```yml
- GRAYLOG_TRANSPORT_EMAIL_ENABLED=true
- GRAYLOG_TRANSPORT_EMAIL_HOSTNAME=smtp.gmail.com
- GRAYLOG_TRANSPORT_EMAIL_PORT=587
- GRAYLOG_TRANSPORT_EMAIL_USE_AUTH=true
- GRAYLOG_TRANSPORT_EMAIL_USE_TLS=true
- GRAYLOG_TRANSPORT_EMAIL_USE_SSL=false
- GRAYLOG_TRANSPORT_EMAIL_AUTH_USERNAME=my_email@gmail.com
- GRAYLOG_TRANSPORT_EMAIL_AUTH_PASSWORD=my_app_password
- GRAYLOG_TRANSPORT_EMAIL_FROM_EMAIL=my_email@gmail.com
- GRAYLOG_TRANSPORT_EMAIL_SUBJECT_PREFIX=[Graylog]
- GRAYLOG_TRANSPORT_EMAIL_WEB_INTERFACE_URL=http://127.0.0.1:9000
```

After editing:

```powershell
docker compose down
docker compose up -d
```

Then in Graylog UI, test an email notification to confirm SMTP works.

---

## 12) Create Stream (Single stream used for all alerts)

We used **one stream** for SSH monitoring.

### Create stream

Streams → Create Stream

* Title: `ssh_auth_new`
* Description: Stream for SSH authentication monitoring using normalised fields.

Save → then start it.

### Add stream rule

Manage Rules → Add stream rule:

* Field: `event_type`
* Value: `sshd`
* Match type: must match exactly

Start stream and confirm it shows **Running**.

### Stream test

Search → select Stream `ssh_auth_new` → last 5 minutes:

```
event_type:sshd
```

You should see SSH logs routed into the stream.

---

## 13) Notifications (Email)

Alerts → Notifications → Create Notification
Create **one notification per alert** (as you documented).

Then use “Test notification” to validate email delivery.

---

## 14) Event Definitions (8 Alerts)

All alerts are created under:

Alerts → Event Definitions → Create Event Definition
Type: **Filter & Aggregation**
Stream: `ssh_auth_new`

All alerts should be built around these fields:

* `message`
* `source_ip`
* `username`
* `action`
* `event_type`

### Alert 1 — SSH Brute Force (same source_ip)

* Query: `event_type:sshd AND message:"Failed password"`
* Group by: `source_ip`
* Condition: `count() >= 5`
* Window: 5 minutes
* Run every: 1 minute

### Alert 2 — Username Targeting (same username)

* Query: `event_type:sshd AND message:failed`
* Group by: `username`
* Condition: `count() >= 5`

### Alert 3 — Root Login Attempt

* Query: `event_type:sshd AND username:root`
* Group by: (none)
* Condition: `count() >= 1`

### Alert 4 — Successful SSH Login

* Query: `event_type:sshd AND message:accepted`
* Group by: `source_ip`
* Condition: `count() >= 1`

### Alert 5 — Many SSH Attempts from One IP (spray/scanning)

* Query: `event_type:sshd`
* Group by: `source_ip`
* Condition: `count() >= 10`

### Alert 6 — Many Attempts Against One User (distributed targeting)

* Query: `event_type:sshd AND message:failed`
* Group by: `username`
* Condition: `count() >= 10`

### Alert 7 — SSH Activity Spike (global)

* Query: `event_type:sshd`
* Group by: (none)
* Condition: `count() >= 30`

### Alert 8 — Invalid User Enumeration

* Query: `event_type:sshd AND message:"invalid user"`
* Group by: `source_ip`
* Condition: `count() >= 3`

> Each event definition must have its notification attached to actually send emails.

---

## 15) Validation (Phase 3 success criteria)

 Logs received into syslog-tcp
 Extractors producing normalized fields
 Stream routes event_type:sshd logs
 Event definitions trigger
 Emails deliver after schedule interval (e.g., 1 minute / 5 minutes)

---

# Export & Handover (Dashboard Teammate + Lecturer-Friendly Setup)

## What gets recreated automatically via bootstrap?

 Inputs + Extractors (Phase 1–2)

## What does NOT automatically recreate via bootstrap (currently)?

 Streams
 Event definitions
 Notifications
 Dashboards

Those are stored inside Graylog DB, so to make the setup lecturer-friendly, we export them using a **Content Pack**.

---

# Phase 3 Content Pack (Export + Share)

## 16) Create a Content Pack (for stream + alerts + notifications)

Go to:

System → Content Packs → Create content pack

Fill:

* Name: `Graylog SSH Monitoring Pack`
* Summary: `Includes SSH stream, brute force detection, and notifications for SOC lab.`
* Description: include what’s inside
* Vendor: your team name
* URL: repo URL (e.g. GitHub link)

### Content selection (tick these)

 Stream
 Event Definitions
 Notifications
(Optionally: Inputs/extractors if you want, but we already handle those with bootstrap.)

Then **Save**.

## 17) Export / Download the Content Pack JSON

On the content pack list:

* Find your pack → “More actions” → **Download**

Save it into repo:

```
content-packs/graylog-ssh-monitoring-pack.json
```

Commit + push to the branch the dashboard guy uses.

---

# Dashboard Handover (Phase 4 — Next Owner)

## What the dashboard person needs from you

1. Lab starts:

```powershell
docker compose up -d
```

2. Inputs/extractors recreated:

```powershell
.\bootstrap.ps1
```

3. Logs arriving via rsyslog over TCP (confirmed)

4. Import Phase 3 content pack:
   System → Content Packs → Upload → select the JSON
   Then Install it.

Once installed, they will see:

* Stream: `ssh_auth_new`
* Event definitions (8 alerts)
* Notifications (email)

---

## Recommended dashboard widgets (based on your parsed fields)

Use stream: `ssh_auth_new`

* **Top attacker source_ip** (count by source_ip)
* **Most targeted usernames** (count by username)
* **Failed vs Accepted** (count by action)
* **SSH activity over time** (event_type:sshd histogram)
* **Brute force events over time** (event definition events count)

---

# Remaining Phases

✅ Phase 1 — Inputs (Complete)
✅ Phase 2 — Extractors / Normalization (Complete)
✅ Phase 3 — Detection + Email Alerts (Complete)
🔜 Phase 4 — Dashboards (Next)
🔜 Phase 5 — Reporting / Export / Final submission packaging

---

# Notes / Common Issues

### “event_type not found”

Almost always logs are being ingested via **syslog-udp**, not **syslog-tcp** (our primary extractors are on syslog-tcp).

Fix: make rsyslog send TCP (omfwd protocol tcp).

### Emails not sending

* Confirm docker-compose SMTP variables are correct
* Confirm Gmail app password is used (not normal password)
* Test notification in Graylog UI


