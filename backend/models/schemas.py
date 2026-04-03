from pydantic import BaseModel
from typing import Literal, Optional


class LogEntry(BaseModel):
    timestamp: str
    source: str
    level: Literal["INFO", "WARNING", "ERROR", "CRITICAL"]
    message: str


class ThreatAnalysis(BaseModel):
    summary: str
    threatLevel: Literal["Low", "Medium", "High", "Critical"]
    affectedSystems: list[str]
    recommendedActions: list[str]
    logEntries: list[LogEntry]


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    content: str
    analysis: Optional[ThreatAnalysis] = None
    logs_queried: int = 0


class StatsResponse(BaseModel):
    failedLogins: int
    errors: int
    networkActivity: int
    suspiciousBehaviour: int
    riskScore: int
    activeAlerts: int
