from fastapi import APIRouter
from models.schemas import ChatRequest, ChatResponse
from services.graylog import graylog, natural_to_lucene
from services.claude import analyze

router = APIRouter(prefix="/api")


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    # 1. Translate natural language → Lucene query for Graylog
    lucene_query = natural_to_lucene(request.message)
    print(f"[Chat] user='{request.message}' → lucene='{lucene_query}'")

    # 2. Pull matching logs from Graylog
    logs = await graylog.search(lucene_query, range_secs=3600, limit=100)
    print(f"[Chat] Graylog returned {len(logs)} log entries")

    # 3. Send logs + original question to Claude for analysis
    analysis = await analyze(request.message, logs)

    return ChatResponse(
        content=f"I've analysed {len(logs)} log entries from Graylog. Here's what I found:",
        analysis=analysis,
        logs_queried=len(logs),
    )
