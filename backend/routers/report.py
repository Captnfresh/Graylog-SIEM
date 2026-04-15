import json
from datetime import datetime
from fastapi import APIRouter
from pydantic import BaseModel
from services.graylog import graylog
from services.claude import get_sync_client
from models.schemas import LogEntry
from config import settings
import anthropic

router = APIRouter(prefix="/api")


class ReportSection(BaseModel):
    executiveSummary: str
    keyInsights: list[str]
    risks: list[dict]
    notableEvents: list[dict]
    visualizations: list[dict]
    recommendations: list[dict]
    overallStatus: str
    statusJustification: str
    boardroomSummary: str
    topTakeaways: list[str]
    logTimeRange: dict
    generatedAt: str


REPORT_SYSTEM_PROMPT = """You are an AI Security and Data Analyst transforming technical log data into clear, executive-level reports for non-technical stakeholders.

Analyse the provided logs and respond with ONLY a valid JSON object (no markdown fences) with this exact structure:

{
  "executiveSummary": "3-5 sentence overview. Highlight key findings, risks, overall system health. No technical jargon.",
  "keyInsights": [
    "Plain-English insight 1 — include dates/times where relevant",
    "Plain-English insight 2",
    "Plain-English insight 3"
  ],
  "risks": [
    {
      "level": "Low|Medium|High",
      "title": "Short risk title",
      "description": "Plain English description",
      "affectedTime": "Date/time range",
      "businessImpact": "What this means for the business"
    }
  ],
  "notableEvents": [
    {
      "datetime": "ISO 8601",
      "what": "Plain English description of what happened",
      "whyItMatters": "Business impact"
    }
  ],
  "visualizations": [
    {
      "type": "bar|line|pie",
      "title": "Chart title",
      "description": "What this chart shows and why it matters to executives"
    }
  ],
  "recommendations": [
    {
      "action": "What should be done (plain English)",
      "priority": "Immediate|Short-term|Long-term",
      "rationale": "Simple explanation of how this reduces risk"
    }
  ],
  "overallStatus": "Healthy|Needs Attention|Critical",
  "statusJustification": "One sentence explanation of the status verdict",
  "boardroomSummary": "2-3 sentences. Suitable for an executive with 30 seconds to spare.",
  "topTakeaways": [
    "Most important insight or risk #1",
    "Most important insight or risk #2",
    "Most important insight or risk #3"
  ]
}

Rules:
- Use plain English throughout — no technical jargon unless explained in brackets
- Tie findings to specific dates and times from the logs
- Focus on business impact, not technical details
- Be concise and decision-focused"""


def _format_logs_for_report(logs: list[LogEntry]) -> str:
    if not logs:
        return "No logs found in the requested time window."
    lines = [
        f"[{log.timestamp}] [{log.level}] {log.source}: {log.message}"
        for log in logs
    ]
    return "\n".join(lines)


def _extract_time_range(logs: list[LogEntry]) -> dict:
    timestamps = [l.timestamp for l in logs if l.timestamp]
    if not timestamps:
        return {"earliest": "N/A", "latest": "N/A"}
    return {"earliest": min(timestamps), "latest": max(timestamps)}


def _fallback_report(logs: list[LogEntry]) -> dict:
    """Rule-based report when Claude API is unavailable."""
    now = datetime.now()
    time_range = _extract_time_range(logs)

    error_logs    = [l for l in logs if l.level in ("ERROR", "CRITICAL")]
    warning_logs  = [l for l in logs if l.level == "WARNING"]
    sources       = list({l.source for l in logs})[:5]

    failed_logins = [l for l in logs if "failed password" in l.message.lower() or "authentication failure" in l.message.lower()]
    suspicious    = [l for l in logs if any(kw in l.message.lower() for kw in ("brute", "scan", "injection", "exfil", "anomaly"))]

    if len(error_logs) >= 5 or suspicious:
        status = "Critical"
    elif len(error_logs) >= 1 or len(warning_logs) >= 3:
        status = "Needs Attention"
    else:
        status = "Healthy"

    risks = []
    if failed_logins:
        risks.append({
            "level": "High",
            "title": "Repeated Login Failures",
            "description": f"{len(failed_logins)} failed authentication attempts detected.",
            "affectedTime": time_range["earliest"] + " – " + time_range["latest"],
            "businessImpact": "Possible unauthorised access attempt. Accounts may be compromised if an attacker succeeds."
        })
    if suspicious:
        risks.append({
            "level": "High",
            "title": "Suspicious Activity Detected",
            "description": f"{len(suspicious)} events flagged as potentially malicious.",
            "affectedTime": time_range["earliest"],
            "businessImpact": "Could indicate an active attack against company infrastructure."
        })
    if error_logs:
        risks.append({
            "level": "Medium",
            "title": "System Errors",
            "description": f"{len(error_logs)} system error events recorded.",
            "affectedTime": time_range["earliest"] + " – " + time_range["latest"],
            "businessImpact": "May cause service degradation or unexpected downtime."
        })
    if not risks:
        risks.append({
            "level": "Low",
            "title": "Normal Operations",
            "description": "No significant threats detected in this period.",
            "affectedTime": time_range["earliest"] + " – " + time_range["latest"],
            "businessImpact": "System operating within expected parameters."
        })

    notable_events = [
        {"datetime": l.timestamp, "what": l.message[:120], "whyItMatters": "Security event requiring review"}
        for l in (error_logs + suspicious)[:5]
    ]

    return {
        "executiveSummary": (
            f"Analysis of {len(logs)} log entries from {time_range['earliest']} to {time_range['latest']}. "
            f"Detected {len(error_logs)} error events and {len(warning_logs)} warnings. "
            f"Systems monitored include: {', '.join(sources)}. "
            + ("Suspicious activity was detected and should be investigated immediately. " if suspicious else "No critical threats identified. ")
            + "(Note: Full AI analysis requires Anthropic API credits.)"
        ),
        "keyInsights": [
            f"{len(failed_logins)} failed login attempts detected — possible brute-force activity" if failed_logins else "No failed login attempts detected in this period",
            f"{len(error_logs)} system errors recorded across {len(sources)} monitored hosts",
            f"Monitoring active on: {', '.join(sources[:3])}",
        ],
        "risks": risks,
        "notableEvents": notable_events or [{"datetime": now.isoformat(), "what": "No significant events recorded", "whyItMatters": "System operating normally"}],
        "visualizations": [
            {"type": "bar",  "title": "Events by Severity Level",       "description": "Shows the count of INFO, WARNING, ERROR, and CRITICAL events — helps executives see where problems are concentrated."},
            {"type": "line", "title": "Login Attempts Over Time",         "description": "Tracks authentication events over the reporting period — spikes may indicate brute-force attacks."},
            {"type": "pie",  "title": "Event Distribution by Source Host","description": "Breaks down which systems generated the most events — highlights which servers need attention."},
        ],
        "recommendations": [
            {"action": "Review and potentially lock accounts with repeated login failures", "priority": "Immediate",   "rationale": "Prevents attackers from gaining access through guessed passwords."},
            {"action": "Investigate flagged suspicious IPs and consider blocking them",     "priority": "Immediate",   "rationale": "Stops ongoing attacks before they escalate."},
            {"action": "Set up automated alerts for error spikes above baseline",            "priority": "Short-term",  "rationale": "Ensures the team is notified the moment something goes wrong."},
            {"action": "Schedule a quarterly security review of all monitored systems",      "priority": "Long-term",   "rationale": "Keeps defences up to date as the threat landscape evolves."},
        ],
        "overallStatus": status,
        "statusJustification": f"Based on {len(error_logs)} errors, {len(warning_logs)} warnings, and {len(suspicious)} suspicious events in the monitored period.",
        "boardroomSummary": (
            f"Our security monitoring reviewed {len(logs)} system events and found the environment is currently {status.lower()}. "
            + (f"There are {len(failed_logins)} unexplained login failures and {len(suspicious)} suspicious events that warrant immediate investigation. " if failed_logins or suspicious else "No immediate threats were identified. ")
            + "The recommendations in this report, if acted upon, will significantly reduce our risk exposure."
        ),
        "topTakeaways": [
            f"{'⚠ ' if failed_logins else '✓ '}{len(failed_logins)} failed login attempts — {'investigate immediately' if failed_logins else 'none detected'}",
            f"{'⚠ ' if error_logs else '✓ '}{len(error_logs)} system errors — {'review for service impact' if error_logs else 'none detected'}",
            f"{'⚠ ' if suspicious else '✓ '}{len(suspicious)} suspicious events — {'active threat possible' if suspicious else 'none detected'}",
        ],
    }


@router.post("/report", response_model=ReportSection)
async def generate_report() -> ReportSection:
    """Generate an executive-level security report from the last hour of Graylog logs."""
    logs = await graylog.search("*", range_secs=3600, limit=200)
    time_range = _extract_time_range(logs)
    generated_at = datetime.now().strftime("%B %d, %Y at %H:%M")

    if not settings.anthropic_api_key:
        data = _fallback_report(logs)
    else:
        logs_text = _format_logs_for_report(logs)
        user_content = (
            f"Generate an executive security report for these Graylog logs:\n\n"
            f"{logs_text}\n\n"
            f"Current date/time: {datetime.now().isoformat()}\n"
            "Respond with the JSON structure only."
        )
        try:
            message = get_sync_client().messages.create(
                model="claude-sonnet-4-6",
                max_tokens=8192,
                system=REPORT_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_content}],
            )
            raw = message.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1].lstrip("json").strip()
            data = json.loads(raw)
        except (anthropic.BadRequestError, anthropic.AuthenticationError,
                anthropic.RateLimitError, json.JSONDecodeError, Exception) as exc:
            print(f"[Report] Claude error: {exc} — using rule-based fallback")
            data = _fallback_report(logs)

    return ReportSection(
        **data,
        logTimeRange=time_range,
        generatedAt=generated_at,
    )
