import json
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from models.schemas import ChatRequest, ChatResponse
from services.graylog import graylog, natural_to_lucene, parse_time_range
from services.claude import analyze, analyze_stream

router = APIRouter(prefix="/api")


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    lucene_query = natural_to_lucene(request.message)
    range_secs   = parse_time_range(request.message)
    print(f"[Chat] user='{request.message}' → lucene='{lucene_query}' range={range_secs}s")

    logs = await graylog.search(lucene_query, range_secs=range_secs, limit=100)
    print(f"[Chat] Graylog returned {len(logs)} log entries")

    analysis = await analyze(request.message, logs, history=request.history)

    return ChatResponse(
        content=f"I've analysed {len(logs)} log entries from Graylog. Here's what I found:",
        analysis=analysis,
        logs_queried=len(logs),
    )


@router.post("/chat/stream")
async def chat_stream(request: ChatRequest) -> StreamingResponse:
    """SSE endpoint — streams the AI summary token by token, then emits the full analysis."""
    lucene_query = natural_to_lucene(request.message)
    range_secs   = parse_time_range(request.message)
    print(f"[Stream] user='{request.message}' → lucene='{lucene_query}' range={range_secs}s")

    logs = await graylog.search(lucene_query, range_secs=range_secs, limit=100)
    print(f"[Stream] Graylog returned {len(logs)} log entries")

    async def event_generator():
        async for event in analyze_stream(request.message, logs, history=request.history):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
