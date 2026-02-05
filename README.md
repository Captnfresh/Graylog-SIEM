# Graylog SIEM Automation – Log Normalisation & Aggregation

This project extends a **Graylog SIEM deployment** with a lightweight **Python automation service** that:
- pulls logs from the Graylog API,
- normalises them into a clean JSON structure, and
- generates aggregated security summaries for easier analysis and reporting.

The stack runs entirely using **Docker Compose**.

---

## What This Automation Does

- Connects to the **Graylog REST API**
- Fetches newly ingested logs at regular intervals
- Normalises raw log messages into structured JSON
- Aggregates events (by event type, severity, source IP)
- Writes:
  - normalised JSON log files
  - aggregated summary JSON reports

This makes raw SIEM data easier to understand, analyse, and report on.

---

## Technology Stack

- Graylog SIEM
- OpenSearch (log storage)
- MongoDB (metadata)
- Python (automation)
- Docker & Docker Compose
- JSON for normalised output

---

## Prerequisites

Before running the project, ensure you have:

- Docker
- Docker Compose
- A Graylog API Token (created in the Graylog UI)

---

## Project Structure

After follwoing the instructions for the first or second steps...
Make sure the graylog is running and then you can copy the graylog API key by doing the following:
## 1) How to get the API Key (Graylog API Token)

1. Open Greylog/Graylog in your browser:
   - `http://localhost:9000`

2. Log in (admin or your user).

3. Go to:
   - **System → Users**
   - Click your username (e.g., **admin**)
   - Click **Edit** (if shown)
   - Find **Tokens** (Personal Access Tokens)

4. Click **Create Token**
   - Give it a name like: `automation-token`
   - Copy the token value (this is your API key)

5. Save it into your `.env` file:
   ```env
   GRAYLOG_API_TOKEN=PASTE_TOKEN_HERE


   run this - `docker compose up -d --build
   then run this -`docker logs -f greylog-log-automation


