import asyncio
import re
import httpx
from datetime import datetime, timedelta
from config import settings
from models.schemas import LogEntry

# Graylog syslog numeric level → our string level
LEVEL_MAP: dict[int, str] = {
    0: "CRITICAL",  # EMERG
    1: "CRITICAL",  # ALERT
    2: "CRITICAL",  # CRIT
    3: "ERROR",     # ERR
    4: "WARNING",   # WARNING
    5: "INFO",      # NOTICE
    6: "INFO",      # INFO
    7: "INFO",      # DEBUG
}

# Reverse: our level string → Graylog numeric levels for count queries
_LEVEL_QUERIES = {
    "CRITICAL": "level:0 OR level:1 OR level:2",
    "ERROR":    "level:3",
    "WARNING":  "level:4",
    "INFO":     "level:5 OR level:6 OR level:7",
}

# ── Natural language → Lucene query translation ───────────────────────────────
_QUERY_MAP: list[tuple[list[str], str]] = [
    (["failed login", "login fail", "authentication fail", "auth fail", "wrong password", "bad password"],
     'message:"Failed password" OR message:"authentication failure" OR message:"Invalid user"'),

    (["brute force", "brute-force", "bruteforce", "multiple fail", "repeated fail"],
     'message:"Failed password" OR message:"brute"'),

    (["root login", "root attempt", "root access"],
     'message:"Failed password for root" OR message:"root"'),

    (["invalid user", "unknown user", "user enumeration"],
     'message:"Invalid user"'),

    (["ssh", "secure shell"],
     'message:ssh OR source:auth* OR source:bastion*'),

    (["port scan", "scanning", "nmap"],
     'message:"Port scan" OR message:scan OR message:nmap'),

    (["sql injection", "sqli", "sql attack"],
     'message:"SQL injection" OR message:"SELECT" OR message:"UNION"'),

    (["vpn", "geolocation", "geo anomaly", "unusual location", "country"],
     'message:VPN OR message:geolocation OR message:"unusual"'),

    (["network", "traffic", "outbound", "exfil", "data transfer"],
     'message:traffic OR message:outbound OR message:network OR source:network*'),

    (["dns", "domain block", "malicious domain"],
     'message:DNS OR message:domain OR source:dns*'),

    (["suspicious", "anomal", "unusual", "threat", "attack"],
     'level:4 OR level:3 OR level:2 OR level:1 OR level:0'),

    (["error", "critical", "failure", "failed"],
     'level:3 OR level:2 OR level:1 OR level:0'),

    (["warning", "warn"],
     'level:4'),

    (["last", "recent", "latest", "what happened", "activity", "all",
      "how many", "count", "total", "summary"],
     '*'),
]


def natural_to_lucene(user_message: str) -> str:
    """Translate a natural language question into a Graylog Lucene search query."""
    msg = user_message.lower()
    for keywords, lucene in _QUERY_MAP:
        if any(kw in msg for kw in keywords):
            return lucene
    return "*"


# ── Natural language → time range ────────────────────────────────────────────

_TIME_PATTERNS: list[tuple[list[str], int]] = [
    (["last 10 min", "past 10 min", "10 min"],               600),
    (["last 15 min", "past 15 min", "15 min"],               900),
    (["last 30 min", "past 30 min", "30 min", "half hour"],  1800),
    (["last 2 hour", "past 2 hour", "2 hour"],               7200),
    (["last 6 hour", "past 6 hour", "6 hour"],               21600),
    (["last 12 hour", "past 12 hour", "12 hour"],            43200),
    (["last 24 hour", "past 24 hour", "24 hour"],            86400),
    (["last hour", "past hour", "one hour"],                  3600),
    (["last week", "past week", "this week", "7 day"],        604800),
]

_WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


def parse_day_query(message: str) -> tuple[datetime, datetime] | None:
    """
    Detect absolute day-based queries and return (from_dt, to_dt).
    Returns None if the query is relative (last N hours, etc.).
    Covers: yesterday, today, Monday, last Tuesday, 2 days ago, etc.
    """
    msg = message.lower()
    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    if "today" in msg or "this morning" in msg or "this afternoon" in msg:
        return today_start, now

    if "yesterday" in msg:
        return today_start - timedelta(days=1), today_start

    # "2 days ago", "3 days ago"
    m = re.search(r"(\d+)\s+days?\s+ago", msg)
    if m:
        n = int(m.group(1))
        start = today_start - timedelta(days=n)
        return start, start + timedelta(days=1)

    # Named weekday: "on Monday", "last Tuesday", "this Wednesday"
    for i, day in enumerate(_WEEKDAYS):
        if day in msg:
            days_back = (now.weekday() - i) % 7
            if days_back == 0 and "last" in msg:
                days_back = 7
            target = today_start - timedelta(days=days_back)
            return target, target + timedelta(days=1)

    return None


def parse_time_range(message: str) -> int:
    """
    Extract a relative time window in seconds from natural language.
    Returns seconds; defaults to 3600.
    Use parse_day_query() first for absolute day queries.
    """
    msg = message.lower()

    if any(kw in msg for kw in ("this morning", "this afternoon", "today")):
        midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return max(int((datetime.now() - midnight).total_seconds()), 3600)

    m = re.search(r"last\s+(\d+)\s+(minute|hour|day|week)s?", msg)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return n * {"minute": 60, "hour": 3600, "day": 86400, "week": 604800}[unit]

    for keywords, secs in _TIME_PATTERNS:
        if any(kw in msg for kw in keywords):
            return secs

    return 3600


class GraylogClient:
    def __init__(self) -> None:
        self.base_url = settings.graylog_host.rstrip("/")
        self.auth = (settings.graylog_username, settings.graylog_password)
        self.headers = {
            "Accept": "application/json",
            "X-Requested-By": "OmniLog",
        }

    # ── Relative search ───────────────────────────────────────────────────────

    async def search(
        self,
        query: str,
        range_secs: int = 3600,
        limit: int = 200,
    ) -> list[LogEntry]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/search/universal/relative",
                    params={"query": query, "range": range_secs, "limit": limit, "sort": "timestamp:desc"},
                    auth=self.auth,
                    headers=self.headers,
                )
                resp.raise_for_status()
                return self._parse_messages(resp.json().get("messages", []))
            except Exception as exc:
                print(f"[Graylog] search error: {exc}")
                return []

    async def count(self, query: str, range_secs: int = 3600) -> int:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/search/universal/relative",
                    params={"query": query, "range": range_secs, "limit": 0},
                    auth=self.auth,
                    headers=self.headers,
                )
                resp.raise_for_status()
                return int(resp.json().get("total_results", 0))
            except Exception as exc:
                print(f"[Graylog] count error ({query!r}): {exc}")
                return 0

    # ── Absolute (day-specific) search ───────────────────────────────────────

    async def search_absolute(
        self,
        query: str,
        from_dt: datetime,
        to_dt: datetime,
        limit: int = 200,
    ) -> list[LogEntry]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/search/universal/absolute",
                    params={
                        "query": query,
                        "from": from_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "to":   to_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "limit": limit,
                        "sort": "timestamp:desc",
                    },
                    auth=self.auth,
                    headers=self.headers,
                )
                resp.raise_for_status()
                return self._parse_messages(resp.json().get("messages", []))
            except Exception as exc:
                print(f"[Graylog] absolute search error: {exc}")
                return []

    async def count_absolute(self, query: str, from_dt: datetime, to_dt: datetime) -> int:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/search/universal/absolute",
                    params={
                        "query": query,
                        "from": from_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "to":   to_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "limit": 0,
                    },
                    auth=self.auth,
                    headers=self.headers,
                )
                resp.raise_for_status()
                return int(resp.json().get("total_results", 0))
            except Exception as exc:
                print(f"[Graylog] absolute count error: {exc}")
                return 0

    # ── Stats: real counts from Graylog, not estimated ───────────────────────

    async def get_stats(
        self,
        query: str,
        range_secs: int | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> dict:
        """
        Return exact counts from Graylog: total + per-level breakdown.
        All queries run in parallel.  Either range_secs OR (from_dt + to_dt) must be given.
        """
        def _level_query(base: str, level_filter: str) -> str:
            if base == "*":
                return level_filter
            return f"({base}) AND ({level_filter})"

        if from_dt and to_dt:
            tasks = [self.count_absolute(query, from_dt, to_dt)]
            for lq in _LEVEL_QUERIES.values():
                tasks.append(self.count_absolute(_level_query(query, lq), from_dt, to_dt))
        else:
            rs = range_secs or 3600
            tasks = [self.count(query, rs)]
            for lq in _LEVEL_QUERIES.values():
                tasks.append(self.count(_level_query(query, lq), rs))

        results = await asyncio.gather(*tasks)
        total = results[0]
        by_level = dict(zip(_LEVEL_QUERIES.keys(), results[1:]))

        return {"total": total, "by_level": by_level}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_messages(self, raw: list[dict]) -> list[LogEntry]:
        entries: list[LogEntry] = []
        for item in raw:
            msg = item.get("message", {})
            level_raw = msg.get("level", 6)
            try:
                level_num = int(level_raw)
            except (TypeError, ValueError):
                level_num = 6
            level_str = LEVEL_MAP.get(level_num, "INFO")
            text = msg.get("message") or msg.get("full_message") or ""
            entries.append(LogEntry(
                timestamp=msg.get("timestamp", ""),
                source=msg.get("source", "unknown"),
                level=level_str,  # type: ignore[arg-type]
                message=text,
            ))
        return entries

    async def health_check(self) -> bool:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/system/lbstatus",
                    auth=self.auth,
                    headers={"X-Requested-By": "OmniLog"},
                )
                return resp.status_code == 200 and resp.text.strip() == "ALIVE"
            except Exception:
                return False


graylog = GraylogClient()
