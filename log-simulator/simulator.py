"""
OmniLog Live Log Simulator — Realistic Mode
============================================
Two operating modes that cycle automatically:

  QUIET (55 min/hr)  — routine IT activity: successful logins, normal traffic,
                        the occasional single failed login or typo.
                        Risk score stays under 40%.

  ATTACK (5 min/hr)  — a coordinated incident: brute-force, port scan,
                        SQL injection, VPN geo-anomaly, data exfil spike.
                        Happens once per hour, lasts ~5 minutes.

Sends events to Graylog via GELF UDP (port 12201).
"""

import json
import math
import os
import random
import socket
import struct
import time
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
GRAYLOG_HOST    = os.environ.get("GRAYLOG_HOST", "graylog")
GRAYLOG_PORT    = int(os.environ.get("GRAYLOG_PORT", 12201))
ATTACK_INTERVAL = int(os.environ.get("ATTACK_INTERVAL_SECS", 3600))  # 1 hour
ATTACK_DURATION = int(os.environ.get("ATTACK_DURATION_SECS", 300))   # 5 minutes
BURST_INTERVAL  = float(os.environ.get("BURST_INTERVAL", 8.0))       # quiet: 1 event every 8s

# ── Data pools ────────────────────────────────────────────────────────────────
ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.47", "91.92.251.103", "194.165.16.11",
    "103.124.106.32", "198.199.77.93", "159.65.21.44", "178.62.194.211",
]
INTERNAL_IPS = [
    "10.0.0.42", "10.0.0.15", "192.168.1.105", "192.168.1.200",
    "172.16.0.5", "10.10.10.23",
]
STAFF_USERS   = ["jsmith", "agreen", "mwilson", "deploy", "svcaccount", "dbadmin"]
SYSTEM_USERS  = ["admin", "root", "ubuntu", "postgres", "git", "test"]
HOSTNAMES     = ["auth-server-01", "web-server-03", "db-server-02",
                 "bastion-host", "vpn-gateway", "firewall-gw",
                 "ids-sensor-02", "network-mon", "dns-server"]
GEO_LOCATIONS = ["Russia", "China", "North Korea", "Romania", "Brazil", "Ukraine"]
PORTS_SCANNED = [22, 23, 80, 443, 3306, 5432, 8080, 8443, 3389, 6379]

EMERG, ALERT, CRIT, ERR, WARN, NOTICE, INFO, DEBUG = 0, 1, 2, 3, 4, 5, 6, 7


# ── GELF sender ───────────────────────────────────────────────────────────────
def _send(sock, host, level, message, extra=None):
    payload = {
        "version": "1.1",
        "host": host,
        "short_message": message,
        "timestamp": time.time(),
        "level": level,
    }
    if extra:
        for k, v in extra.items():
            payload[f"_{k}"] = v
    raw = json.dumps(payload).encode("utf-8")
    if len(raw) <= 8192:
        sock.sendto(raw, (GRAYLOG_HOST, GRAYLOG_PORT))
        return
    import zlib
    compressed = zlib.compress(raw)
    chunk_size = 1420
    chunks = math.ceil(len(compressed) / chunk_size)
    msg_id = os.urandom(8)
    for i in range(chunks):
        chunk = (b"\x1e\x0f" + msg_id + struct.pack("BB", i, chunks)
                 + compressed[i * chunk_size:(i + 1) * chunk_size])
        sock.sendto(chunk, (GRAYLOG_HOST, GRAYLOG_PORT))


# ── QUIET MODE events (routine, low-risk) ────────────────────────────────────

def quiet_successful_login(sock):
    user = random.choice(STAFF_USERS)
    ip   = random.choice(INTERNAL_IPS)
    host = random.choice(["auth-server-01", "bastion-host"])
    _send(sock, host, INFO,
          f"Accepted publickey for {user} from {ip} port {random.randint(1024, 65535)} ssh2",
          {"event_type": "ssh_auth_success", "src_ip": ip, "username": user, "program": "sshd"})


def quiet_session_opened(sock):
    user = random.choice(STAFF_USERS)
    _send(sock, random.choice(["auth-server-01", "bastion-host"]), INFO,
          f"pam_unix(sshd:session): session opened for user {user}",
          {"event_type": "session_open", "username": user, "program": "sshd"})


def quiet_session_closed(sock):
    user = random.choice(STAFF_USERS)
    _send(sock, random.choice(["auth-server-01", "bastion-host"]), INFO,
          f"pam_unix(sshd:session): session closed for user {user}",
          {"event_type": "session_close", "username": user, "program": "sshd"})


def quiet_sudo_command(sock):
    user = random.choice(STAFF_USERS)
    cmds = ["apt-get update", "systemctl status nginx", "df -h", "tail -f /var/log/syslog", "ps aux"]
    host = random.choice(HOSTNAMES)
    _send(sock, host, INFO,
          f"sudo: {user} : TTY=pts/0 ; COMMAND={random.choice(cmds)}",
          {"event_type": "sudo_command", "username": user, "program": "sudo"})


def quiet_cron_job(sock):
    jobs = [
        "(/usr/sbin/anacron) started job `cron.daily`",
        "run-parts(/etc/cron.daily): finished logrotate",
        "CRON: pam_unix(cron:session): session opened for user root",
        "run-parts(/etc/cron.hourly): starting 0anacron",
    ]
    _send(sock, random.choice(HOSTNAMES), INFO, random.choice(jobs),
          {"event_type": "cron", "program": "CRON"})


def quiet_normal_network(sock):
    src = random.choice(INTERNAL_IPS)
    kb  = random.randint(10, 800)
    _send(sock, "network-mon", INFO,
          f"Outbound connection established: {src} → 8.8.8.8:443 ({kb} KB transferred)",
          {"event_type": "normal_traffic", "src_ip": src})


def quiet_dns_lookup(sock):
    domains = ["github.com", "apt.releases.hashicorp.com", "registry.npmjs.org",
               "pypi.org", "dl.google.com", "updates.microsoft.com"]
    ip = random.choice(INTERNAL_IPS)
    _send(sock, "dns-server", INFO,
          f"DNS query resolved: {random.choice(domains)} from {ip}",
          {"event_type": "dns_ok", "src_ip": ip})


def quiet_single_failed_login(sock):
    """One failed login — happens occasionally, not suspicious on its own."""
    user = random.choice(STAFF_USERS)
    ip   = random.choice(INTERNAL_IPS)
    host = random.choice(["auth-server-01", "bastion-host"])
    _send(sock, host, WARN,
          f"Failed password for {user} from {ip} port {random.randint(1024, 65535)} ssh2",
          {"event_type": "ssh_auth_failure", "src_ip": ip, "username": user, "program": "sshd"})


def quiet_vpn_login(sock):
    user = random.choice(STAFF_USERS)
    ip   = random.choice(INTERNAL_IPS)
    _send(sock, "vpn-gateway", INFO,
          f"VPN connection established for {user} from {ip} (home office)",
          {"event_type": "vpn_ok", "src_ip": ip, "username": user})


def quiet_firewall_allow(sock):
    src  = random.choice(INTERNAL_IPS)
    port = random.choice([80, 443, 8080, 22])
    _send(sock, "firewall-gw", INFO,
          f"ALLOW TCP {src}:{random.randint(1024,65535)} → 0.0.0.0:{port}",
          {"event_type": "fw_allow", "src_ip": src})


# ── ATTACK MODE events (dangerous, triggered once per hour) ──────────────────

def attack_brute_force(sock):
    ip   = random.choice(ATTACKER_IPS)
    user = random.choice(SYSTEM_USERS)
    host = "auth-server-01"
    count = random.randint(40, 80)
    print(f"  [ATTACK] Brute-force: {count} attempts → {user}@{host} from {ip}")
    for _ in range(count):
        _send(sock, host, WARN,
              f"Failed password for {user} from {ip} port {random.randint(1024, 65535)} ssh2",
              {"event_type": "ssh_auth_failure", "src_ip": ip, "username": user, "program": "sshd"})
        time.sleep(0.05)
    # Account lockout triggered
    _send(sock, host, ERR,
          f"Multiple failed login attempts detected — account lockout triggered for {user}",
          {"event_type": "account_lockout", "src_ip": ip, "username": user, "program": "sshd"})


def attack_root_attempts(sock):
    ip = random.choice(ATTACKER_IPS)
    for _ in range(random.randint(5, 10)):
        _send(sock, "bastion-host", ERR,
              f"Failed password for root from {ip} port {random.randint(1024, 65535)} ssh2",
              {"event_type": "ssh_root_attempt", "src_ip": ip, "username": "root", "program": "sshd"})
        time.sleep(0.3)


def attack_port_scan(sock):
    ip    = random.choice(ATTACKER_IPS)
    ports = random.sample(PORTS_SCANNED, k=random.randint(6, 10))
    print(f"  [ATTACK] Port scan from {ip} → ports {ports}")
    _send(sock, "firewall-gw", WARN,
          f"Port scan detected from {ip} targeting ports {','.join(map(str, ports))}",
          {"event_type": "port_scan", "src_ip": ip, "ports": str(ports)})
    _send(sock, "ids-sensor-02", CRIT,
          f"Possible reconnaissance activity from {ip} — {len(ports)} ports probed",
          {"event_type": "recon_detected", "src_ip": ip})


def attack_sql_injection(sock):
    payloads = [
        "' OR '1'='1", "'; DROP TABLE users;--",
        "UNION SELECT username,password FROM users",
        "1' AND SLEEP(5)--", "admin'--",
    ]
    ip = random.choice(ATTACKER_IPS)
    print(f"  [ATTACK] SQL injection from {ip}")
    for _ in range(random.randint(3, 6)):
        _send(sock, "web-server-03", ERR,
              f"SQL injection attempt blocked from {ip}: {random.choice(payloads)}",
              {"event_type": "sql_injection", "src_ip": ip, "program": "nginx"})
        time.sleep(0.5)


def attack_vpn_geo_anomaly(sock):
    user = random.choice(STAFF_USERS)
    geo  = random.choice(GEO_LOCATIONS)
    ip   = random.choice(ATTACKER_IPS)
    print(f"  [ATTACK] VPN geo-anomaly: {user} connecting from {geo}")
    _send(sock, "vpn-gateway", WARN,
          f"VPN connection from unusual geolocation: {geo} (user: {user}) from {ip}",
          {"event_type": "vpn_geo_anomaly", "src_ip": ip, "username": user, "geo": geo})


def attack_data_exfil(sock):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(ATTACKER_IPS)
    mb  = random.randint(200, 800)
    print(f"  [ATTACK] Data exfil suspect: {src} → {dst} {mb}MB")
    _send(sock, "network-mon", WARN,
          f"Unusual outbound traffic spike: {src} → {dst} ({mb} MB in 60s)",
          {"event_type": "data_exfil_suspect", "src_ip": src, "dst_ip": dst})
    _send(sock, "ids-sensor-02", ERR,
          f"Potential data exfiltration detected from {src} to external IP {dst}",
          {"event_type": "exfil_alert", "src_ip": src, "dst_ip": dst})


def attack_invalid_user_enum(sock):
    ip       = random.choice(ATTACKER_IPS)
    host     = "bastion-host"
    bogus    = ["oracle", "hadoop", "ftp", "pi", "test123", "admin2", "guest", "support"]
    print(f"  [ATTACK] User enumeration from {ip}")
    for user in random.sample(bogus, k=random.randint(4, 7)):
        _send(sock, host, WARN,
              f"Invalid user {user} from {ip} port {random.randint(1024, 65535)}",
              {"event_type": "ssh_invalid_user", "src_ip": ip, "username": user, "program": "sshd"})
        time.sleep(0.2)


# ── Quiet event table (low-risk, routine) ─────────────────────────────────────
QUIET_EVENTS = [
    (quiet_successful_login,    30),
    (quiet_session_opened,      15),
    (quiet_session_closed,      15),
    (quiet_normal_network,      15),
    (quiet_dns_lookup,          10),
    (quiet_cron_job,             8),
    (quiet_sudo_command,         5),
    (quiet_vpn_login,            5),
    (quiet_firewall_allow,       8),
    (quiet_single_failed_login,  4),  # rare — not suspicious alone
]
_QUIET_POOL = [fn for fn, w in QUIET_EVENTS for _ in range(w)]

# ── Attack sequence (fired in order during the attack window) ─────────────────
ATTACK_SEQUENCE = [
    attack_invalid_user_enum,   # reconnaissance first
    attack_port_scan,
    attack_brute_force,         # escalate
    attack_root_attempts,
    attack_sql_injection,       # pivot to web
    attack_vpn_geo_anomaly,
    attack_data_exfil,          # exfiltration last
]


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    print(f"OmniLog Realistic Simulator → {GRAYLOG_HOST}:{GRAYLOG_PORT}")
    print(f"Attack window: {ATTACK_DURATION}s every {ATTACK_INTERVAL}s ({ATTACK_INTERVAL//60} min)")
    print("Waiting 10s for Graylog to be ready...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    time.sleep(10)

    last_attack = time.time() - ATTACK_INTERVAL + 120  # first attack 2 min after start
    event_count = 0
    in_attack   = False
    attack_step = 0
    attack_end  = 0

    while True:
        now = time.time()
        ts  = datetime.now(timezone.utc).strftime("%H:%M:%S")

        # ── Check if it's time to start an attack ────────────────────────────
        if not in_attack and (now - last_attack) >= ATTACK_INTERVAL:
            in_attack   = True
            attack_step = 0
            attack_end  = now + ATTACK_DURATION
            last_attack = now
            print(f"\n{'='*60}")
            print(f"[{ts}] ⚠  ATTACK WINDOW STARTED — {ATTACK_DURATION}s of hostile activity")
            print(f"{'='*60}\n")

        # ── ATTACK MODE ───────────────────────────────────────────────────────
        if in_attack:
            if now >= attack_end or attack_step >= len(ATTACK_SEQUENCE):
                in_attack = False
                print(f"\n[{ts}] ✓ Attack window ended — returning to quiet mode\n")
                continue

            fn = ATTACK_SEQUENCE[attack_step]
            print(f"[{ts}] ATTACK step {attack_step+1}/{len(ATTACK_SEQUENCE)}: {fn.__name__}")
            try:
                fn(sock)
            except Exception as e:
                print(f"  ERROR: {e}")
            attack_step += 1
            time.sleep(20)  # space out attack steps

        # ── QUIET MODE ────────────────────────────────────────────────────────
        else:
            event_count += 1
            fn = random.choice(_QUIET_POOL)
            try:
                fn(sock)
            except Exception as e:
                print(f"  ERROR sending quiet event: {e}")

            if event_count % 20 == 0:
                mins_to_attack = max(0, int((ATTACK_INTERVAL - (now - last_attack)) / 60))
                print(f"[{ts}] Quiet mode — {event_count} events sent | next attack in ~{mins_to_attack} min")

            time.sleep(BURST_INTERVAL)


if __name__ == "__main__":
    main()
