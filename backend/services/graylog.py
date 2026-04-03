import asyncio
import httpx
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

# ── Natural language → Lucene query translation ───────────────────────────────
# Maps keywords in a user's chat message to proper Graylog/Lucene search queries
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

    (["last", "recent", "latest", "what happened", "activity", "all"],
     '*'),
]


def natural_to_lucene(user_message: str) -> str:
    """Translate a natural language question into a Graylog Lucene search query."""
    msg = user_message.lower()
    for keywords, lucene in _QUERY_MAP:
        if any(kw in msg for kw in keywords):
            return lucene
    # Default: return all logs
    return "*"


class GraylogClient:
    def __init__(self) -> None:
        self.base_url = settings.graylog_host.rstrip("/")
        self.auth = (settings.graylog_username, settings.graylog_password)
        self.headers = {
            "Accept": "application/json",
            "X-Requested-By": "OmniLog",
        }

    async def search(
        self,
        query: str,
        range_secs: int = 3600,
        limit: int = 100,
    ) -> list[LogEntry]:
        """
        query: a Lucene query string (not natural language).
        Use natural_to_lucene() to convert user messages first.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/search/universal/relative",
                    params={
                        "query": query,
                        "range": range_secs,
                        "limit": limit,
                        "sort": "timestamp:desc",
                    },
                    auth=self.auth,
                    headers=self.headers,
                )
                resp.raise_for_status()
                data = resp.json()
                return self._parse_messages(data.get("messages", []))
            except Exception as exc:
                print(f"[Graylog] search error: {exc}")
                return []

    async def count(self, query: str, range_secs: int = 3600) -> int:
        """Count matching messages using the search endpoint (count endpoint removed in GL 6.x)."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/search/universal/relative",
                    params={
                        "query": query,
                        "range": range_secs,
                        "limit": 0,   # 0 = metadata only, no messages returned
                    },
                    auth=self.auth,
                    headers=self.headers,
                )
                resp.raise_for_status()
                data = resp.json()
                return int(data.get("total_results", 0))
            except Exception as exc:
                print(f"[Graylog] count error ({query!r}): {exc}")
                return 0

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
            entries.append(
                LogEntry(
                    timestamp=msg.get("timestamp", ""),
                    source=msg.get("source", "unknown"),
                    level=level_str,  # type: ignore[arg-type]
                    message=text,
                )
            )
        return entries

    async def health_check(self) -> bool:
        # lbstatus returns plain text "ALIVE" — must NOT send Accept: application/json
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
