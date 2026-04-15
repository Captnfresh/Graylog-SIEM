import asyncio
import json
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from models.schemas import ChatRequest, ChatResponse
from services.graylog import graylog, natural_to_lucene, parse_time_range, parse_day_query
from services.claude import analyze, analyze_stream

router = APIRouter(prefix="/api")


async def _fetch_logs_and_stats(message: str):
    """
    Resolve query, time window, then fetch logs + real counts from Graylog in parallel.
    Returns (logs, stats, time_label).
    stats = {"total": int, "by_level": {"CRITICAL": int, "ERROR": int, ...}}
    """
    lucene_query = natural_to_lucene(message)
    day_range    = parse_day_query(message)

    if day_range:
        from_dt, to_dt = day_range
        time_label = f"{from_dt.strftime('%Y-%m-%d')} (full day)"
        logs, stats = await asyncio.gather(
            graylog.search_absolute(lucene_query, from_dt, to_dt, limit=500),
            graylog.get_stats(lucene_query, from_dt=from_dt, to_dt=to_dt),
        )
    else:
        range_secs = parse_time_range(message)
        mins = range_secs // 60
        time_label = f"last {mins} minutes" if mins < 120 else f"last {mins // 60} hours"
        logs, stats = await asyncio.gather(
            graylog.search(lucene_query, range_secs=range_secs, limit=500),
            graylog.get_stats(lucene_query, range_secs=range_secs),
        )

    print(
        f"[Chat] query='{message}' lucene='{lucene_query}' window='{time_label}' "
        f"total={stats['total']} fetched={len(logs)}"
    )
    return logs, stats, time_label


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    logs, stats, time_label = await _fetch_logs_and_stats(request.message)
    analysis = await analyze(
        request.message, logs,
        stats=stats, time_label=time_label,
        history=request.history,
    )
    return ChatResponse(
        content=f"Analysed {stats['total']:,} logs ({time_label}).",
        analysis=analysis,
        logs_queried=stats["total"],
    )


@router.post("/chat/stream")
async def chat_stream(request: ChatRequest) -> StreamingResponse:
    """SSE endpoint — streams AI summary token by token, then emits full analysis."""
    logs, stats, time_label = await _fetch_logs_and_stats(request.message)

    async def event_generator():
        async for event in analyze_stream(
            request.message, logs,
            stats=stats, time_label=time_label,
            history=request.history,
        ):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
