from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from routers import chat, logs, report

app = FastAPI(title="OmniLog API", version="1.0.0", description="AI-powered SIEM assistant backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat.router)
app.include_router(logs.router)
app.include_router(report.router)


@app.get("/")
def root():
    return {"service": "OmniLog API", "version": "1.0.0", "docs": "/docs"}
