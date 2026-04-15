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

SYSTEM_PROMPT = """You are OmniLog, an expert AI cybersecurity analyst embedded in a Graylog SIEM platform.
Help IT and security teams understand security events in plain language and act fast.

You may receive a conversation history — use it to give contextual, connected answers (e.g. "as I mentioned earlier…").

Respond with a single valid JSON object only — no markdown fences, no text outside the JSON.

Required JSON structure:
{
  "summary": "Conversational expert explanation. Name specific IPs, users, timestamps, attack patterns. Reference prior conversation context if relevant.",
  "threatLevel": "Low" | "Medium" | "High" | "Critical",
  "affectedSystems": ["list of hosts/systems involved"],
  "recommendedActions": ["specific", "actionable", "steps for the team"],
  "logEntries": [
    {"timestamp": "ISO 8601", "source": "host", "level": "INFO|WARNING|ERROR|CRITICAL", "message": "log line"}
  ],
  "followUps": [
    "3 natural follow-up questions the analyst would likely want to ask next, specific to what was found"
  ]
}

Rules:
- logEntries: max 10 most relevant entries supporting your analysis
- followUps: make them specific (e.g. "Which accounts had the most failures?" not "Tell me more")
- Always output valid JSON only — the response is parsed programmatically"""


# Streaming variant: plain-text summary first, then separator, then JSON
STREAM_SYSTEM_PROMPT = """You are OmniLog, an expert AI cybersecurity analyst embedded in a Graylog SIEM platform.
Help IT and security teams understand security events in plain language and act fast.

You may receive a conversation history — use it to give contextual, connected answers.

RESPONSE FORMAT — follow this exactly, no deviations:

First, write 2-4 sentences of plain-text analysis. Be specific: name IPs, users, ports, patterns. Reference prior conversation context if relevant.

Then on a new line write exactly:
---ANALYSIS---

Then on the next line write a single JSON object:
{
  "threatLevel": "Low" | "Medium" | "High" | "Critical",
  "affectedSystems": ["list of hosts/systems"],
  "recommendedActions": ["specific", "actionable", "steps"],
  "logEntries": [
    {"timestamp": "ISO 8601", "source": "host", "level": "INFO|WARNING|ERROR|CRITICAL", "message": "log line"}
  ],
  "followUps": [
    "3 natural follow-up questions specific to what was found"
  ]
}

Rules:
- logEntries: max 10 most relevant entries
- followUps: specific questions (e.g. "Which IP triggered the most alerts?")
- Nothing outside the format above — no preamble, no closing text"""

SEPARATOR = "---ANALYSIS---"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_logs(logs: list[LogEntry]) -> str:
    if not logs:
        return "No logs found in Graylog for this time window."
    lines = [
        f"[{log.timestamp}] [{log.level}] {log.source}: {log.message}"
        for log in logs[:50]
    ]
    return "\n".join(lines)


def _build_messages(
    query: str,
    history: list[HistoryMessage],
    logs: list[LogEntry],
    streaming: bool = False,
) -> list[dict]:
    """Build Claude messages array including conversation history."""
    messages: list[dict] = []

    # Interleave prior turns (skip incomplete or empty entries)
    for h in history:
        if h.content.strip():
            messages.append({"role": h.role, "content": h.content})

    # Ensure messages alternate properly (Claude requires user/assistant alternation)
    # If last message is from assistant, that's fine — we're about to add a user message
    # If somehow history ends with user, add a placeholder assistant message
    if messages and messages[-1]["role"] == "user":
        messages.append({"role": "assistant", "content": "Understood. What else would you like to know?"})

    suffix = "\n\nRespond with the required format only." if streaming else "\n\nRespond with the JSON structure only."
    logs_text = _format_logs(logs)
    messages.append({
        "role": "user",
        "content": (
            f"Graylog logs (last hour):\n{logs_text}\n\n"
            f"Security team question: {query}"
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
        tips.append("What's the normal baseline for these events?")

    if len(tips) < 3:
        tips.append("Show me a summary of all security events today.")

    return tips[:3]


def _fallback_analyze(query: str, logs: list[LogEntry]) -> ThreatAnalysis:
    q = query.lower()
    relevant = logs[:10]

    sources = list({l.source for l in relevant})
    critical_ips = list({
        word for log in relevant
        for word in log.message.split()
        if word.count(".") == 3 and all(p.isdigit() for p in word.split("."))
    })[:5]

    error_logs   = [l for l in relevant if l.level in ("ERROR", "CRITICAL")]
    warning_logs = [l for l in relevant if l.level == "WARNING"]

    if len(error_logs) >= 3 or any("brute" in l.message.lower() for l in relevant):
        threat = "Critical"
    elif len(error_logs) >= 1 or len(warning_logs) >= 3:
        threat = "High"
    elif len(warning_logs) >= 1:
        threat = "Medium"
    else:
        threat = "Low"

    if not logs:
        summary = (
            "No logs matched your query in the current time window. "
            "The system is monitoring but no relevant events were found. "
            "(Rule-based mode — add Anthropic API credits for full Claude AI analysis.)"
        )
    else:
        top_msgs = "; ".join(l.message[:80] for l in relevant[:3])
        summary = (
            f"Analysed {len(logs)} Graylog log entries. "
            f"Detected {len(error_logs)} error-level and {len(warning_logs)} warning-level events. "
            f"Top events: {top_msgs}. "
            f"Involved systems: {', '.join(sources[:4])}. "
            + (f"External IPs observed: {', '.join(critical_ips)}. " if critical_ips else "")
            + "(Rule-based analysis — add Anthropic API credits to enable full Claude AI insights.)"
        )

    actions = [
        f"Review logs on: {', '.join(sources[:3])}",
        "Check firewall rules for any suspicious source IPs",
        "Correlate events with user activity in Active Directory",
        "Enable full AI analysis by adding credits at console.anthropic.com",
    ]
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
    """Instant rule-based analysis — never calls the Claude API. Used for live alerts."""
    return _fallback_analyze(query, logs)


async def analyze(
    query: str,
    logs: list[LogEntry],
    history: list[HistoryMessage] | None = None,
) -> ThreatAnalysis:
    """Non-streaming analysis for the standard /chat endpoint."""
    if not settings.anthropic_api_key:
        return _fallback_analyze(query, logs)

    messages = _build_messages(query, history or [], logs, streaming=False)

    try:
        message = get_sync_client().messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return _parse_response(message.content[0].text)

    except (anthropic.BadRequestError, anthropic.AuthenticationError,
            anthropic.RateLimitError) as exc:
        print(f"[Claude] API error ({type(exc).__name__}): {exc}")
        return _fallback_analyze(query, logs)

    except Exception as exc:
        print(f"[Claude] Unexpected error: {exc}")
        return _fallback_analyze(query, logs)


async def analyze_stream(
    query: str,
    logs: list[LogEntry],
    history: list[HistoryMessage] | None = None,
):
    """
    Async generator for the /chat/stream SSE endpoint.
    Yields dicts:
      {"type": "text", "delta": "<char>"}        — summary characters as they arrive
      {"type": "done", "analysis": {...}, "logs_queried": N}  — final parsed analysis
    """
    if not settings.anthropic_api_key:
        result = _fallback_analyze(query, logs)
        for ch in result.summary:
            yield {"type": "text", "delta": ch}
            await asyncio.sleep(0.004)
        yield {"type": "done", "analysis": result.model_dump(), "logs_queried": len(logs)}
        return

    messages = _build_messages(query, history or [], logs, streaming=True)
    full_text = ""

    # Positions for streaming the pre-separator summary
    sep_idx: int | None = None      # index where SEPARATOR starts in full_text
    streamed_to = 0                  # how many pre-separator chars we've yielded

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
                    # Check if separator has appeared yet
                    found = full_text.find(SEPARATOR)
                    if found != -1:
                        sep_idx = found
                        # Yield all summary chars up to (but not including) the separator
                        for ch in full_text[streamed_to:sep_idx]:
                            yield {"type": "text", "delta": ch}
                        streamed_to = sep_idx
                    else:
                        # Keep a safety buffer of SEPARATOR length to avoid splitting across chunks
                        safe_end = max(streamed_to, len(full_text) - len(SEPARATOR))
                        for ch in full_text[streamed_to:safe_end]:
                            yield {"type": "text", "delta": ch}
                        streamed_to = safe_end
                # After separator found: just buffer (don't yield JSON tokens)

        # Parse the final response
        if sep_idx is not None:
            summary_text = full_text[:sep_idx].strip()
            json_text = full_text[sep_idx + len(SEPARATOR):].strip()
            data = json.loads(json_text)
            data["summary"] = summary_text
            analysis = ThreatAnalysis(**data)
        else:
            # Separator not found — fall back to full JSON parse
            analysis = _parse_response(full_text)

        yield {"type": "done", "analysis": analysis.model_dump(), "logs_queried": len(logs)}

    except Exception as exc:
        print(f"[Claude Stream] Error: {exc}")
        result = _fallback_analyze(query, logs)
        yield {"type": "done", "analysis": result.model_dump(), "logs_queried": len(logs)}
