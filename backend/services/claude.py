import json
import anthropic
from config import settings
from models.schemas import LogEntry, ThreatAnalysis

_client: anthropic.Anthropic | None = None


def get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    return _client


SYSTEM_PROMPT = """You are OmniLog, an expert AI cybersecurity analyst embedded in a Graylog SIEM platform.
Your role is to help IT and security teams understand security events in plain language and take the right action fast.

You will receive log entries from Graylog and a question from the security team.
You MUST respond with a single valid JSON object — no markdown fences, no explanation outside the JSON.

Required JSON structure:
{
  "summary": "Conversational expert explanation of what the logs show. Mention specific IPs, users, timestamps, and attack patterns you identify. Explain what is happening and why it matters.",
  "threatLevel": "Low" | "Medium" | "High" | "Critical",
  "affectedSystems": ["list of systems/hosts involved"],
  "recommendedActions": ["specific", "actionable", "steps for the team"],
  "logEntries": [
    {
      "timestamp": "ISO 8601 timestamp",
      "source": "source host or system",
      "level": "INFO" | "WARNING" | "ERROR" | "CRITICAL",
      "message": "the log line"
    }
  ]
}

Rules:
- logEntries must contain the most relevant logs (max 10) that support your analysis
- Be specific: name the IPs, users, ports, and systems involved
- recommendedActions must be concrete steps, not vague advice
- If there are no logs, say so in the summary and set threatLevel to "Low"
- Always output valid JSON — the response will be parsed programmatically"""


def _format_logs(logs: list[LogEntry]) -> str:
    if not logs:
        return "No logs found in Graylog for this time window."
    lines = [
        f"[{log.timestamp}] [{log.level}] {log.source}: {log.message}"
        for log in logs[:50]
    ]
    return "\n".join(lines)


def _parse_response(raw: str) -> ThreatAnalysis:
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1].lstrip("json").strip() if len(parts) > 1 else text
    data = json.loads(text)
    return ThreatAnalysis(**data)


# ── Rule-based fallback (no Claude API required) ──────────────────────────────
def _fallback_analyze(query: str, logs: list[LogEntry]) -> ThreatAnalysis:
    """
    Used when Claude API is unavailable (no credits, no key, rate-limited).
    Produces a rule-based analysis directly from the Graylog logs.
    """
    q = query.lower()
    relevant = logs[:10]

    sources      = list({l.source for l in relevant})
    critical_ips = list({
        word for log in relevant
        for word in log.message.split()
        if word.count(".") == 3 and all(p.isdigit() for p in word.split("."))
    })[:5]

    error_logs   = [l for l in relevant if l.level in ("ERROR", "CRITICAL")]
    warning_logs = [l for l in relevant if l.level == "WARNING"]

    # Determine threat level from log severity mix
    if len(error_logs) >= 3 or any("brute" in l.message.lower() for l in relevant):
        threat = "Critical"
    elif len(error_logs) >= 1 or len(warning_logs) >= 3:
        threat = "High"
    elif len(warning_logs) >= 1:
        threat = "Medium"
    else:
        threat = "Low"

    # Build a plain-English summary from actual log content
    if not logs:
        summary = (
            "No logs matched your query in the current time window. "
            "The system is monitoring but no relevant events were found. "
            "(Note: AI analysis is running in rule-based mode — add Anthropic API credits for full Claude analysis.)"
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
    )


async def analyze(query: str, logs: list[LogEntry]) -> ThreatAnalysis:
    # Skip Claude entirely if no API key configured
    if not settings.anthropic_api_key:
        return _fallback_analyze(query, logs)

    logs_text    = _format_logs(logs)
    user_content = (
        f"Graylog logs (last hour):\n{logs_text}\n\n"
        f"Security team question: {query}\n\n"
        "Respond with the JSON structure only."
    )

    try:
        message = get_client().messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        return _parse_response(message.content[0].text)

    except anthropic.BadRequestError as exc:
        # Low credits, invalid key, or account issue — degrade gracefully
        print(f"[Claude] BadRequestError (likely low credits): {exc}")
        return _fallback_analyze(query, logs)

    except anthropic.AuthenticationError as exc:
        print(f"[Claude] AuthenticationError (bad API key): {exc}")
        return _fallback_analyze(query, logs)

    except anthropic.RateLimitError as exc:
        print(f"[Claude] RateLimitError: {exc}")
        return _fallback_analyze(query, logs)

    except Exception as exc:
        print(f"[Claude] Unexpected error: {exc}")
        return _fallback_analyze(query, logs)
