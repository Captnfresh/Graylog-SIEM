import json
import asyncio
import anthropic
from config import settings
from models.schemas import LogEntry, ThreatAnalysis, HistoryMessage

_sync_client: anthropic.Anthropic | None = None
_async_client: anthropic.AsyncAnthropic | None = None


def get_sync_client() -> anthropic.Anthropic:
    global _sync_client
    if _sync_client is None:
        _sync_client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    return _sync_client


def get_async_client() -> anthropic.AsyncAnthropic:
    global _async_client
    if _async_client is None:
        _async_client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    return _async_client


# ── System prompts ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are OmniLog, a precise AI security analyst embedded in a Graylog SIEM.

Every message begins with a "=== VERIFIED GRAYLOG DATA ===" block containing EXACT counts
fetched directly from the Graylog database. These numbers are ground truth.

ACCURACY RULES — NON-NEGOTIABLE:
1. When asked "how many logs", state TOTAL_LOGS exactly as given. Never round, estimate, or say "approximately".
2. Use the exact CRITICAL/ERROR/WARNING/INFO counts from the verified block.
3. If a fact is not in the provided data, say "I don't have that in the current log window" — never invent it.
4. Always cite the TIME_WINDOW so the user knows the scope.
5. Lead with the number or key fact. Be direct. Do not waffle.

Respond with a single valid JSON object only — no markdown fences, no text outside JSON.

{
  "summary": "Lead with the key fact or number. Then 2-4 sentences of specific analysis naming IPs, users, timestamps. Reference conversation history if relevant. No jargon.",
  "threatLevel": "Low|Medium|High|Critical",
  "affectedSystems": ["list of hosts/systems from the logs"],
  "recommendedActions": ["specific", "actionable", "steps"],
  "logEntries": [
    {"timestamp": "ISO 8601", "source": "host", "level": "INFO|WARNING|ERROR|CRITICAL", "message": "log line"}
  ],
  "followUps": [
    "3 specific follow-up questions based on what was actually found"
  ]
}

logEntries: max 10 most relevant entries.
followUps: make them specific — e.g. "Which accounts had the most failures?" not "Tell me more"."""


STREAM_SYSTEM_PROMPT = """You are OmniLog, a precise AI security analyst embedded in a Graylog SIEM.

Every message begins with a "=== VERIFIED GRAYLOG DATA ===" block containing EXACT counts
fetched directly from the Graylog database. These numbers are ground truth.

ACCURACY RULES — NON-NEGOTIABLE:
1. When asked "how many logs", state TOTAL_LOGS exactly. Never round or estimate.
2. Use the exact CRITICAL/ERROR/WARNING/INFO breakdown from the verified block.
3. If a fact isn't in the provided data, say so — never invent details.
4. Always cite the TIME_WINDOW in your answer.
5. Lead with the answer. Be direct and specific.

RESPONSE FORMAT — follow exactly:

Write 2-4 sentences of direct analysis. Start with the key fact or number. Name specific IPs, users, timestamps. Reference prior conversation if relevant.

Then on a new line write exactly:
---ANALYSIS---

Then a single JSON object:
{
  "threatLevel": "Low|Medium|High|Critical",
  "affectedSystems": ["hosts from the logs"],
  "recommendedActions": ["specific", "actionable", "steps"],
  "logEntries": [
    {"timestamp": "ISO 8601", "source": "host", "level": "INFO|WARNING|ERROR|CRITICAL", "message": "log line"}
  ],
  "followUps": [
    "3 specific follow-up questions based on what was actually found"
  ]
}

Nothing outside this format. No preamble, no closing remarks."""

SEPARATOR = "---ANALYSIS---"


# ── Context builder ───────────────────────────────────────────────────────────

def _build_verified_header(stats: dict, time_label: str, log_count: int) -> str:
    """Prepend exact Graylog counts as ground truth. Claude must cite these, not estimate."""
    by_level = stats.get("by_level", {})
    total    = stats.get("total", log_count)
    lines = [
        "=== VERIFIED GRAYLOG DATA ===",
        f"TIME_WINDOW    : {time_label}",
        f"TOTAL_LOGS     : {total:,}",
        f"  CRITICAL     : {by_level.get('CRITICAL', 0):,}",
        f"  ERROR        : {by_level.get('ERROR', 0):,}",
        f"  WARNING      : {by_level.get('WARNING', 0):,}",
        f"  INFO         : {by_level.get('INFO', 0):,}",
        f"SAMPLE_FETCHED : {log_count} representative entries shown below",
        "=== END VERIFIED DATA ===",
    ]
    return "\n".join(lines)


def _format_logs(logs: list[LogEntry]) -> str:
    if not logs:
        return "No log entries returned for this query."
    lines = [
        f"[{log.timestamp}] [{log.level}] {log.source}: {log.message}"
        for log in logs[:100]
    ]
    return "\n".join(lines)


def _build_messages(
    query: str,
    history: list[HistoryMessage],
    logs: list[LogEntry],
    stats: dict,
    time_label: str,
    streaming: bool = False,
) -> list[dict]:
    messages: list[dict] = []

    for h in history:
        if h.content.strip():
            messages.append({"role": h.role, "content": h.content})

    if messages and messages[-1]["role"] == "user":
        messages.append({"role": "assistant", "content": "Understood. What else would you like to know?"})

    verified_header = _build_verified_header(stats, time_label, len(logs))
    logs_text = _format_logs(logs)
    suffix = "\n\nRespond with the required format only." if streaming else "\n\nRespond with the JSON structure only."

    messages.append({
        "role": "user",
        "content": (
            f"{verified_header}\n\n"
            f"=== LOG SAMPLE ===\n{logs_text}\n=== END SAMPLE ===\n\n"
            f"Question: {query}"
            f"{suffix}"
        ),
    })
    return messages


def _parse_response(raw: str) -> ThreatAnalysis:
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1].lstrip("json").strip() if len(parts) > 1 else text
    data = json.loads(text)
    return ThreatAnalysis(**data)


# ── Rule-based fallback ───────────────────────────────────────────────────────

def _fallback_followups(query: str, logs: list[LogEntry], critical_ips: list[str]) -> list[str]:
    q = query.lower()
    tips: list[str] = []
    if critical_ips:
        tips.append(f"What other activity came from {critical_ips[0]}?")
    if "ssh" in q or "login" in q or "fail" in q:
        tips.append("Is this a brute-force pattern or isolated failures?")
        tips.append("Which user accounts were targeted most?")
    elif "network" in q or "traffic" in q or "scan" in q:
        tips.append("Are these connections going to known malicious IPs?")
        tips.append("What ports are being scanned?")
    elif "error" in q or "critical" in q:
        tips.append("Should I escalate these errors to the on-call team?")
        tips.append("Are these errors linked to a recent deployment?")
    else:
        tips.append("Are there related events in the last 24 hours?")
        tips.append("Show me a breakdown of events by severity level.")
    if len(tips) < 3:
        tips.append("Which hosts generated the most log volume today?")
    return tips[:3]


def _fallback_analyze(
    query: str,
    logs: list[LogEntry],
    stats: dict | None = None,
    time_label: str = "last hour",
) -> ThreatAnalysis:
    by_level = (stats or {}).get("by_level", {})
    total    = (stats or {}).get("total", len(logs))

    critical_count = by_level.get("CRITICAL", 0)
    error_count    = by_level.get("ERROR", 0)
    warning_count  = by_level.get("WARNING", 0)
    info_count     = by_level.get("INFO", 0)

    relevant     = logs[:10]
    sources      = list({l.source for l in relevant})
    critical_ips = list({
        word for log in relevant
        for word in log.message.split()
        if word.count(".") == 3 and all(p.isdigit() for p in word.split("."))
    })[:5]

    failed_logins = [l for l in logs if "failed password" in l.message.lower() or "authentication failure" in l.message.lower()]
    suspicious    = [l for l in logs if any(kw in l.message.lower() for kw in ("brute", "scan", "injection", "exfil", "anomaly"))]

    if critical_count >= 5 or suspicious:
        threat = "Critical"
    elif critical_count >= 1 or error_count >= 3:
        threat = "High"
    elif error_count >= 1 or warning_count >= 3:
        threat = "Medium"
    else:
        threat = "Low"

    if not logs:
        summary = (
            f"No logs found in Graylog for the {time_label} window. "
            "Nothing matched this query. "
            "(Rule-based mode — add Anthropic API credits for full AI analysis.)"
        )
    else:
        summary = (
            f"Graylog recorded {total:,} total logs in the {time_label} window: "
            f"{critical_count:,} CRITICAL, {error_count:,} ERROR, {warning_count:,} WARNING, {info_count:,} INFO. "
        )
        if failed_logins:
            summary += f"{len(failed_logins)} failed login attempts detected. "
        if suspicious:
            summary += f"{len(suspicious)} suspicious events flagged. "
        if critical_ips:
            summary += f"Active external IPs: {', '.join(critical_ips)}. "
        summary += "(Rule-based analysis — add Anthropic API credits for full AI insights.)"

    actions = [f"Review logs on: {', '.join(sources[:3])}",
               "Check firewall rules for suspicious source IPs",
               "Correlate with user activity in Active Directory"]
    if critical_ips:
        actions.insert(0, f"Investigate or block IPs: {', '.join(critical_ips)}")

    return ThreatAnalysis(
        summary=summary,
        threatLevel=threat,  # type: ignore[arg-type]
        affectedSystems=sources or ["unknown"],
        recommendedActions=actions,
        logEntries=relevant,
        followUps=_fallback_followups(query, logs, critical_ips),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def quick_analyze(query: str, logs: list[LogEntry]) -> ThreatAnalysis:
    """Instant rule-based analysis — used for live alerts, never calls Claude API."""
    return _fallback_analyze(query, logs)


async def analyze(
    query: str,
    logs: list[LogEntry],
    stats: dict | None = None,
    time_label: str = "last hour",
    history: list[HistoryMessage] | None = None,
) -> ThreatAnalysis:
    if not settings.anthropic_api_key:
        return _fallback_analyze(query, logs, stats, time_label)

    messages = _build_messages(query, history or [], logs, stats or {}, time_label, streaming=False)
    try:
        message = get_sync_client().messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return _parse_response(message.content[0].text)
    except (anthropic.BadRequestError, anthropic.AuthenticationError, anthropic.RateLimitError) as exc:
        print(f"[Claude] API error ({type(exc).__name__}): {exc}")
        return _fallback_analyze(query, logs, stats, time_label)
    except Exception as exc:
        print(f"[Claude] Unexpected error: {exc}")
        return _fallback_analyze(query, logs, stats, time_label)


async def analyze_stream(
    query: str,
    logs: list[LogEntry],
    stats: dict | None = None,
    time_label: str = "last hour",
    history: list[HistoryMessage] | None = None,
):
    """
    Async generator for /chat/stream SSE endpoint.
    Yields {"type": "text", "delta": "..."} then {"type": "done", "analysis": {...}, "logs_queried": N}
    """
    total = (stats or {}).get("total", len(logs))

    if not settings.anthropic_api_key:
        result = _fallback_analyze(query, logs, stats, time_label)
        for ch in result.summary:
            yield {"type": "text", "delta": ch}
            await asyncio.sleep(0.004)
        yield {"type": "done", "analysis": result.model_dump(), "logs_queried": total}
        return

    messages = _build_messages(query, history or [], logs, stats or {}, time_label, streaming=True)
    full_text = ""
    sep_idx: int | None = None
    streamed_to = 0

    try:
        async with get_async_client().messages.stream(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=STREAM_SYSTEM_PROMPT,
            messages=messages,
        ) as stream:
            async for chunk in stream.text_stream:
                full_text += chunk

                if sep_idx is None:
                    found = full_text.find(SEPARATOR)
                    if found != -1:
                        sep_idx = found
                        for ch in full_text[streamed_to:sep_idx]:
                            yield {"type": "text", "delta": ch}
                        streamed_to = sep_idx
                    else:
                        safe_end = max(streamed_to, len(full_text) - len(SEPARATOR))
                        for ch in full_text[streamed_to:safe_end]:
                            yield {"type": "text", "delta": ch}
                        streamed_to = safe_end

        if sep_idx is not None:
            summary_text = full_text[:sep_idx].strip()
            json_text    = full_text[sep_idx + len(SEPARATOR):].strip()
            data = json.loads(json_text)
            data["summary"] = summary_text
            analysis = ThreatAnalysis(**data)
        else:
            analysis = _parse_response(full_text)

        yield {"type": "done", "analysis": analysis.model_dump(), "logs_queried": total}

    except Exception as exc:
        print(f"[Claude Stream] Error: {exc}")
        result = _fallback_analyze(query, logs, stats, time_label)
        yield {"type": "done", "analysis": result.model_dump(), "logs_queried": total}
