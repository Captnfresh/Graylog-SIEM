import asyncio
import json
import time
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from models.schemas import StatsResponse
from services.graylog import graylog
from services.claude import quick_analyze

router = APIRouter(prefix="/api")

# ── Queries reused by stats + alert detection ─────────────────────────────────
_Q_FAILED   = 'message:"Failed password" OR message:"Invalid user" OR message:"authentication failure"'
_Q_SUSPIC   = 'message:brute OR message:anomaly OR message:suspicious OR message:"Port scan" OR message:"SQL injection" OR message:"exfil" OR message:"geolocation"'
_Q_ERRORS   = "level:3 OR level:2 OR level:1 OR level:0"
_Q_NETWORK  = "message:traffic OR message:outbound OR message:scan OR source:network* OR source:firewall*"
_Q_ALERTS_Q = 'message:brute OR message:anomaly OR message:suspicious OR message:unusual OR message:"Port scan" OR level:2 OR level:1'
_Q_ALERT_LOGS = f"{_Q_SUSPIC} OR {_Q_ERRORS}"


async def _compute_stats() -> StatsResponse:
    """Shared stats computation used by /stats and /alerts/stream."""
    (
        failed_recent, suspicious_recent, errors_recent,
        failed_total, errors_total, network_total, suspicious_total,
    ) = await asyncio.gather(
        graylog.count(_Q_FAILED,  range_secs=300),
        graylog.count(_Q_SUSPIC,  range_secs=300),
        graylog.count(_Q_ERRORS,  range_secs=300),
        graylog.count(_Q_FAILED),
        graylog.count(_Q_ERRORS),
        graylog.count(_Q_NETWORK),
        graylog.count(_Q_ALERTS_Q),
    )
    raw_risk = (failed_recent * 2) + (errors_recent * 4) + (suspicious_recent * 8)
    risk = min(100, raw_risk)
    return StatsResponse(
        failedLogins=failed_total,
        errors=errors_total,
        networkActivity=network_total,
        suspiciousBehaviour=suspicious_total,
        riskScore=risk,
        activeAlerts=failed_recent + suspicious_recent,
    )


@router.get("/logs/recent")
async def get_recent_logs(limit: int = Query(50, le=200)):
    logs = await graylog.search("*", range_secs=3600, limit=limit)
    return {"logs": [log.model_dump() for log in logs], "total": len(logs)}


@router.get("/logs/search")
async def search_logs(
    q: str = Query("*"),
    range_secs: int = Query(3600, le=86400),
    limit: int = Query(50, le=200),
):
    logs = await graylog.search(q, range_secs=range_secs, limit=limit)
    return {"logs": [log.model_dump() for log in logs], "total": len(logs)}


@router.get("/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    return await _compute_stats()


@router.get("/health")
async def health():
    is_healthy = await graylog.health_check()
    return {"status": "ok" if is_healthy else "degraded", "graylog": is_healthy}


@router.get("/alerts/stream")
async def alerts_stream() -> StreamingResponse:
    """
    SSE stream that monitors risk score every 30 seconds.
    Emits an 'alert' event when risk spikes above 60 (with 5-minute cooldown).
    Emits a 'heartbeat' event each cycle so the client knows the connection is alive.
    """
    async def generate():
        prev_risk     = 0
        last_alert_at = 0.0
        ALERT_THRESHOLD    = 60   # risk % that triggers an alert
        RECOVERY_THRESHOLD = 40   # risk must have been below this before we alert again
        COOLDOWN_SECS      = 300  # 5 minutes between alerts
        POLL_INTERVAL      = 30   # seconds between checks

        while True:
            try:
                stats = await _compute_stats()
                risk  = stats.riskScore
                now   = time.time()

                spike = (
                    risk > ALERT_THRESHOLD
                    and prev_risk <= RECOVERY_THRESHOLD
                    and (now - last_alert_at) > COOLDOWN_SECS
                )

                if spike:
                    # Grab the suspicious logs that caused the spike
                    alert_logs = await graylog.search(_Q_ALERT_LOGS, range_secs=300, limit=20)
                    analysis   = quick_analyze(
                        "What suspicious activity triggered this security alert?",
                        alert_logs,
                    )
                    event = {
                        "type":        "alert",
                        "riskScore":   risk,
                        "analysis":    analysis.model_dump(),
                        "logsQueried": len(alert_logs),
                    }
                    yield f"data: {json.dumps(event)}\n\n"
                    last_alert_at = now
                    print(f"[Alerts] Fired alert — risk {prev_risk}% → {risk}%")
                else:
                    # Heartbeat so the client knows the connection is alive
                    yield f"data: {json.dumps({'type': 'heartbeat', 'riskScore': risk})}\n\n"

                prev_risk = risk

            except Exception as exc:
                print(f"[Alerts] Error in stream: {exc}")
                yield f"data: {json.dumps({'type': 'heartbeat', 'riskScore': 0})}\n\n"

            await asyncio.sleep(POLL_INTERVAL)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
