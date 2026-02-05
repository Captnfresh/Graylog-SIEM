#!/usr/bin/env python3
"""
Graylog Log Normaliser + Aggregator (Poller)

What it does:
- Polls Graylog for new messages (since last run)
- Normalises raw log fields into a consistent JSON schema
- Writes JSONL output (easy to parse later)
- Creates an aggregation summary JSON (counts per IP, event type, etc.)

How it works:
- Uses Graylog Search API (messages) with a time window and "since" checkpoint.
- Stores checkpoint in a local file so you don't duplicate results.

Requirements:
- pip install requests python-dateutil
"""

import os
import json
import time
from datetime import datetime, timezone
from collections import Counter, defaultdict

import requests
from dateutil import parser as dt_parser

# ----------------------------
# Config (Environment Variables)
# ----------------------------
GRAYLOG_URL = os.getenv("GRAYLOG_URL", "http://localhost:9000")  # e.g., http://graylog:9000 in docker network
GRAYLOG_API_TOKEN = os.getenv("GRAYLOG_API_TOKEN", "")          # Personal Access Token
GRAYLOG_VERIFY_TLS = os.getenv("GRAYLOG_VERIFY_TLS", "true").lower() == "true"

# Query settings
GRAYLOG_QUERY = os.getenv("GRAYLOG_QUERY", "*")  # e.g. stream:auth OR event_type:failed_login
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))
BATCH_LIMIT = int(os.getenv("BATCH_LIMIT", "500"))  # max messages per poll (tune this)

# Output
OUT_DIR = os.getenv("OUT_DIR", "./out")
CHECKPOINT_FILE = os.getenv("CHECKPOINT_FILE", "./checkpoint.json")

# ----------------------------
# Helpers
# ----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ensure_out_dir():
    os.makedirs(OUT_DIR, exist_ok=True)

def load_checkpoint() -> dict:
    """
    Keeps track of last seen timestamp so we only fetch new logs next time.
    """
    if not os.path.exists(CHECKPOINT_FILE):
        return {"since": None}
    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"since": None}

def save_checkpoint(since_iso: str):
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
        json.dump({"since": since_iso}, f, indent=2)

def graylog_headers() -> dict:
    if not GRAYLOG_API_TOKEN:
        raise RuntimeError("GRAYLOG_API_TOKEN is missing. Set it as an environment variable.")
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {GRAYLOG_API_TOKEN}",
        "X-Requested-By": "graylog-automation",
    }

def safe_get(d: dict, keys, default=None):
    """
    Try multiple keys from Graylog message fields (since field names vary).
    """
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default

def parse_any_timestamp(value):
    """
    Graylog often provides 'timestamp' like 2026-02-05T10:00:01.123Z
    """
    if not value:
        return None
    try:
        dt = dt_parser.parse(str(value))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

# ----------------------------
# Normalisation Logic
# ----------------------------
def normalise_message(msg: dict) -> dict:
    """
    Convert a Graylog message into a consistent schema.
    """
    fields = msg.get("message", {}) if "message" in msg else msg

    # core
    ts_raw = safe_get(fields, ["timestamp", "gl2_processing_timestamp", "event.timestamp"])
    ts = parse_any_timestamp(ts_raw)
    ts_iso = ts.isoformat() if ts else utc_now_iso()

    source = safe_get(fields, ["source", "host", "hostname"], default="unknown")
    raw_message = safe_get(fields, ["message", "full_message", "log", "msg"], default="")

    # network-ish fields (vary by input type)
    src_ip = safe_get(fields, ["src_ip", "source_ip", "client_ip", "gl2_remote_ip", "remote_ip", "ip"], default=None)
    dst_ip = safe_get(fields, ["dst_ip", "destination_ip"], default=None)
    username = safe_get(fields, ["user", "username", "account", "ssh_user"], default=None)

    # event_type can be added by pipelines/extractors; if missing, we infer
    event_type = safe_get(fields, ["event_type", "event.type", "type"], default=None)
    if not event_type:
        text = (raw_message or "").lower()
        if "failed password" in text or "authentication failure" in text:
            event_type = "failed_login"
        elif "ddos" in text or "syn flood" in text:
            event_type = "possible_ddos"
        elif "sudo" in text or "privilege" in text:
            event_type = "privilege_activity"
        elif "error" in text or "critical" in text or "failed" in text:
            event_type = "system_error"
        else:
            event_type = "generic"

    # severity (simple inference; you can make this stricter)
    severity = safe_get(fields, ["severity", "level", "log_level"], default=None)
    if not severity:
        txt = (raw_message or "").lower()
        if "critical" in txt:
            severity = "CRITICAL"
        elif "error" in txt:
            severity = "ERROR"
        elif "warn" in txt:
            severity = "WARN"
        else:
            severity = "INFO"

    # Build a clean, consistent JSON object
    normalised = {
        "timestamp": ts_iso,
        "source": source,
        "event_type": event_type,
        "severity": str(severity).upper(),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "username": username,
        "message": raw_message,
        # Keep minimal context for traceability
        "graylog_streams": fields.get("streams", None),
        "graylog_id": fields.get("_id", fields.get("id", None)),
    }

    # Remove null keys to keep JSON tidy
    return {k: v for k, v in normalised.items() if v not in (None, "", [])}

# ----------------------------
# Aggregation Logic
# ----------------------------
def aggregate_events(events: list[dict]) -> dict:
    """
    Create summary counts to understand patterns quickly.
    """
    counts_by_type = Counter(e.get("event_type", "unknown") for e in events)
    counts_by_sev = Counter(e.get("severity", "UNKNOWN") for e in events)
    counts_by_ip = Counter(e.get("source_ip", "unknown") for e in events if e.get("source_ip"))

    # top IPs per event type (useful for brute-force / ddos spotting)
    top_ip_by_type = defaultdict(Counter)
    for e in events:
        et = e.get("event_type", "unknown")
        ip = e.get("source_ip")
        if ip:
            top_ip_by_type[et][ip] += 1

    return {
        "generated_at": utc_now_iso(),
        "total_events": len(events),
        "counts_by_event_type": counts_by_type.most_common(),
        "counts_by_severity": counts_by_sev.most_common(),
        "top_source_ips": counts_by_ip.most_common(20),
        "top_source_ips_by_event_type": {
            et: c.most_common(10) for et, c in top_ip_by_type.items()
        },
    }

# ----------------------------
# Graylog Fetch (Polling)
# ----------------------------
def fetch_graylog_messages(since_iso: str | None) -> list[dict]:
    """
    Uses Graylog search/universal/relative or absolute time range.
    We'll use absolute range if we have 'since', otherwise last 5 minutes.
    """
    endpoint = f"{GRAYLOG_URL.rstrip('/')}/api/search/universal/absolute"

    # If first run, look back 5 minutes
    if since_iso is None:
        now = datetime.now(timezone.utc)
        frm = (now.timestamp() - 300)  # 5 minutes
        from_dt = datetime.fromtimestamp(frm, tz=timezone.utc)
        to_dt = now
    else:
        from_dt = dt_parser.parse(since_iso)
        if not from_dt.tzinfo:
            from_dt = from_dt.replace(tzinfo=timezone.utc)
        to_dt = datetime.now(timezone.utc)

    params = {
        "query": GRAYLOG_QUERY,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "limit": BATCH_LIMIT,
        "offset": 0,
        "filter": "streams:all",  # optional; adjust if you target a stream
    }

    r = requests.get(endpoint, headers=graylog_headers(), params=params, verify=GRAYLOG_VERIFY_TLS, timeout=20)
    r.raise_for_status()
    data = r.json()

    # Graylog returns "messages": [{"message": {...}}, ...]
    return data.get("messages", [])

def write_jsonl(path: str, events: list[dict]):
    with open(path, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

def write_json(path: str, obj: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

# ----------------------------
# Main loop
# ----------------------------
def main():
    ensure_out_dir()
    checkpoint = load_checkpoint()
    since = checkpoint.get("since")

    print(f"[*] Graylog URL: {GRAYLOG_URL}")
    print(f"[*] Query: {GRAYLOG_QUERY}")
    print(f"[*] Starting since: {since}")

    while True:
        try:
            msgs = fetch_graylog_messages(since)
            if not msgs:
                print("[*] No new messages.")
                time.sleep(POLL_SECONDS)
                continue

            # Normalise
            normalised = [normalise_message(m) for m in msgs]

            # Determine newest timestamp to update checkpoint
            newest_ts = None
            for e in normalised:
                dt = parse_any_timestamp(e.get("timestamp"))
                if dt and (newest_ts is None or dt > newest_ts):
                    newest_ts = dt
            if newest_ts:
                since = newest_ts.isoformat()
                save_checkpoint(since)

            # Write JSONL (daily file)
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            jsonl_path = os.path.join(OUT_DIR, f"normalized_{day}.jsonl")
            write_jsonl(jsonl_path, normalised)

            # Aggregate and write summary
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            agg = aggregate_events(normalised)
            agg_path = os.path.join(OUT_DIR, f"aggregate_{stamp}.json")
            write_json(agg_path, agg)

            print(f"[+] Pulled {len(msgs)} msgs | wrote {len(normalised)} normalised -> {jsonl_path}")
            print(f"[+] Aggregation saved -> {agg_path}")
        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
