import asyncio
from fastapi import APIRouter, Query
from models.schemas import StatsResponse
from services.graylog import graylog

router = APIRouter(prefix="/api")


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
    # Use a 5-minute window for risk scoring (reflects current activity)
    # Use a 1-hour window for sidebar counts (total events)
    (
        failed_recent, suspicious_recent, errors_recent,
        failed_total, errors_total, network_total, suspicious_total,
    ) = await asyncio.gather(
        # 5-min window for risk
        graylog.count('message:"Failed password" OR message:"Invalid user" OR message:"authentication failure"', range_secs=300),
        graylog.count('message:brute OR message:anomaly OR message:suspicious OR message:"Port scan" OR message:"SQL injection" OR message:"exfil" OR message:"geolocation"', range_secs=300),
        graylog.count("level:3 OR level:2 OR level:1 OR level:0", range_secs=300),
        # 1-hour window for sidebar counts
        graylog.count('message:"Failed password" OR message:"Invalid user" OR message:"authentication failure"'),
        graylog.count("level:3 OR level:2 OR level:1 OR level:0"),
        graylog.count("message:traffic OR message:outbound OR message:scan OR source:network* OR source:firewall*"),
        graylog.count('message:brute OR message:anomaly OR message:suspicious OR message:unusual OR message:"Port scan" OR level:2 OR level:1'),
    )

    # Risk score based on last 5 minutes only:
    # - Normal quiet activity:  0–3 failed logins  → 0–20% risk
    # - Elevated (few failures): 4–10             → 20–40% risk
    # - Attack window (many):   >10              → 40–100% risk
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


@router.get("/health")
async def health():
    is_healthy = await graylog.health_check()
    return {"status": "ok" if is_healthy else "degraded", "graylog": is_healthy}
