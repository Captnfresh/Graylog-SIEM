# Documentation: Log Ingestion, Parsing, and Export (Graylog)

---

# Getting Started (Environment Setup)

This section allows any team member to spin up the lab and get identical parsing results.

---

## 1️. Clone Repository

```bash
git clone https://github.com/Captnfresh/Greylog-SIEM.git
cd graylog-lab
git checkout feature/phase2-graylog-parsing
copy .env.example .env
```

---

## 2️. Configure `.env`

Open `.env` in VS Code and set:

```env
THIS HAS BEEN PROVIDED TO ALL TEAM MEMBERS
```

### Meaning

| Variable           | Purpose                       |
| ------------------ | ----------------------------- |
| PASSWORD_SECRET    | Internal Graylog security key |
| ROOT_PASSWORD_SHA2 | Admin password hash           |
| HTTP_EXTERNAL_URI  | Graylog web address           |
| OPENSEARCH_HOSTS   | Log database backend          |

---

## 3️. Start Environment

```bash
docker compose up -d
```

Wait 1–2 minutes for containers to fully start.

---

## 4️. Access Graylog UI

Open:

```
http://localhost:9000
```

Login:

```
THIS HAS BEEN PROVIDED TO ALL THE TEAM MEMBERS
```

---

## 5️. Run Bootstrap (Auto-Configuration)

Bootstrap automatically recreates:

- Inputs
- Extractors
- Parsing rules

```powershell
.\bootstrap.ps1
```

This removes manual UI setup and ensures reproducibility.

---

## 6️. Send Test Log

Run in PowerShell:

```powershell
$server = "127.0.0.1"
$port   = 1514
$msg    = "<134>Feb 03 15:00:00 windows-host sshd[123]: BOOTSTRAP_TEST Failed password for invalid user test from 10.10.10.10 port 5555 ssh2"

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($server, $port)

$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$writer.WriteLine($msg)

$writer.Dispose()
$stream.Dispose()
$client.Close()
```

---

## 7️. Verify Parsing

In Graylog:

* Go to **Search**
* Time Range → Last 15 minutes
* Search:

```
BOOTSTRAP_TEST
```

You should see fields:

✅ `source_ip`
✅ `username`
✅ `action`
✅ `event_type`

If visible → parsing is working.

---









# Overview (Non-Technical Summary)

This project uses **Graylog** to centralise logs for security monitoring. We set up multiple “log doors” (called **inputs**) so logs can enter Graylog. We then “organised” those logs using **extractors** so Graylog can identify important details like:

* Source IP address (where the activity came from)
* Username (who was targeted / used)
* Action (failed or successful login)
* Event type (e.g., SSH authentication log)

Finally, we exported the Graylog configuration to JSON files and stored them in GitHub so every team member can reproduce the same setup.

---

## Technology Used

* Graylog (Docker)
* MongoDB (Graylog config storage)
* OpenSearch (log storage / search backend)
* GitHub (version control + collaboration)

---

## Phase 1 — Log Ingestion (Inputs)

### What is an Input?

An **input** is a listening endpoint in Graylog where logs are received.
Think of inputs like “ports/doors” that accept logs.

### Inputs Created

We created and ran three inputs:

1. **Syslog TCP** (port 1514)
2. **Syslog UDP** (port 1514)
3. **GELF UDP** (port 12201)

> Note: We used port **1514** (instead of 514) to avoid privileged port restrictions.

### Docker Port Mapping (compose)

Graylog container ports mapped to the host:

* `9000` → Graylog Web UI
* `1514/tcp` → Syslog TCP
* `1514/udp` → Syslog UDP
* `12201/udp` → GELF UDP

---

## Phase 1 — Testing Log Ingestion (Windows Host)

### A) Test Syslog TCP (Windows → Graylog)

We used PowerShell to send a Syslog message over TCP to Graylog:

```powershell
$tcp = New-Object System.Net.Sockets.TcpClient("127.0.0.1",1514)
$stream = $tcp.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$writer.WriteLine("<13>Graylog PHASE1-TCP test from Windows")
$writer.Close()
$tcp.Close()
```

**Verify in Graylog:**

* Search time range: Last 5 minutes
* Search term: `PHASE1-TCP`

---

### B) Test Syslog UDP (Windows → Graylog)

We sent a UDP syslog message:

```powershell
$udp = New-Object System.Net.Sockets.UdpClient
$msg = "<13>Graylog PHASE1-UDP test from Windows"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
$udp.Send($bytes,$bytes.Length,"127.0.0.1",1514)
$udp.Close()
```

**Verify in Graylog:** Search `PHASE1-UDP`

---

### C) Test GELF UDP (Windows → Graylog)

We sent a GELF-formatted JSON message via UDP:

```powershell
$udp = New-Object System.Net.Sockets.UdpClient
$json = '{"version":"1.1","host":"windows","short_message":"PHASE1-GELF test","level":5}'
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$udp.Send($bytes,$bytes.Length,"127.0.0.1",12201)
$udp.Close()
```

**Verify in Graylog:** Search `PHASE1-GELF`

---

## Phase 2 — Parsing & Normalisation (Extractors)

### What is an Extractor?

An **extractor** takes a raw log message and extracts key values into new structured fields.

Example raw log:

```
Failed password for invalid user admin from 192.168.1.50 port 22 ssh2
```

After extractors, Graylog creates fields like:

* `source_ip = 192.168.1.50`
* `username = admin`
* `action = failed`
* `event_type = sshd`

This is essential for dashboards, alerts, and reporting.

---

## Phase 2 — Create a Realistic SSH Log (for parsing)

To build and test extractors, we generated a realistic SSH “failed login” message:

```powershell
$tcp = New-Object System.Net.Sockets.TcpClient("127.0.0.1",1514)
$stream = $tcp.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$writer.WriteLine("<13>Feb 2 12:08:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2")
$writer.Close()
$tcp.Close()
```

**Verify in Graylog:** Search `Failed password`

---

## Extractors Implemented (Syslog TCP Input)

> Important: Extractors are linked to the **input** they were created on.
> In this project we attached these extractors to **Syslog TCP** because that is our main ingestion path.

### 1) Extract Source IP

* Field: `source_ip`
* Regex:

```
from (\d+\.\d+\.\d+\.\d+)
```

### 2) Extract Username

* Field: `username`
* Regex:

```
user (\S+) from
```

### 3) Extract Action (failed/accepted)

* Field: `action`
* Regex:

```
(failed|accepted) password
```

### 4) Extract Event Type (sshd)

* Field: `event_type`
* Regex:

```
(sshd)\[
```

---

## Why Parsing Matters for the Assessment

Extractors enable:

* Dashboards (e.g., top attacker IPs, failed login trends)
* Detection rules (e.g., brute force alerts)
* Automated reports (counts by user/IP/action)
* Faster querying and better visualisation

Without parsing, logs remain “one long text line” and the SIEM cannot easily detect patterns.

---

## Exporting Configuration to GitHub (Team Collaboration)

### Why export?

Inputs and extractors are stored inside Graylog’s internal database (MongoDB).
They **do not automatically appear in GitHub** unless exported.

Exporting ensures:

* Teammates can reproduce the same parsing
* No “works only on my machine” problems
* Config becomes version-controlled

---

## Export Steps (Using Graylog REST API)

### 1) Create a Personal Access Token

In Graylog UI:

* Profile → Personal Access Tokens → Create Token

### 2) Export Inputs to JSON

```powershell
$token = "YOURTOKEN"
curl.exe -u "$token`:token" -H "Accept: application/json" `
"http://localhost:9000/api/system/inputs" `
-o graylog-config/graylog-inputs.json
```

### 3) Identify Syslog TCP input ID

Syslog TCP input ID was:

```
697e8ec1874c7256f78da673
```

### 4) Export Extractors for Syslog TCP

```powershell
$token = "YOURTOKEN"
$inputId = "697e8ec1874c7256f78da673"

curl.exe -u "$token`:token" -H "Accept: application/json" `
"http://localhost:9000/api/system/inputs/$inputId/extractors" `
-o graylog-config/graylog-extractors-syslog-tcp.json
```

Expected output contained:

```
"total": 4
```

---

## Version Control (Branch Workflow)

We committed exports into a dedicated branch:

* Branch: `feature/phase2-graylog-parsing`
* Folder created in repo:

```
/graylog-config/
  graylog-inputs.json
  graylog-extractors-syslog-tcp.json
```

This allows teammates to pull the branch and verify the exported config exists.


## Next Steps (Phase 3)

* Build dashboards using the extracted fields
* Add detection rules (brute force scenario)
* Create reporting automation scripts


