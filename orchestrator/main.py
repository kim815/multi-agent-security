import logging

from fastapi import FastAPI

from dotenv import load_dotenv

from orchestrator.github_webhook import router as github_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)

# Load local development env vars (safe no-op if .env doesn't exist)
load_dotenv()

app = FastAPI(title="Multi-Agent Security Orchestrator", version="0.1.0")
app.include_router(github_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
