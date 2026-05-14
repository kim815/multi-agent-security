import hmac
import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Request

from orchestrator.workflow import run_workflow

logger = logging.getLogger(__name__)
router = APIRouter()


def _verify_signature(body: bytes, signature_header: Optional[str], secret: Optional[str]) -> None:
    """Verify GitHub webhook signature if secret is configured.

    Supports X-Hub-Signature-256: sha256=... (preferred) and falls back to X-Hub-Signature: sha1=...
    """

    if not secret:
        return

    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing webhook signature")

    try:
        algo, sig = signature_header.split("=", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid signature header") from exc

    algo = algo.lower()
    if algo not in {"sha256", "sha1"}:
        raise HTTPException(status_code=401, detail="Unsupported signature algorithm")

    digestmod = hashlib.sha256 if algo == "sha256" else hashlib.sha1
    computed = hmac.new(secret.encode("utf-8"), msg=body, digestmod=digestmod).hexdigest()

    if not hmac.compare_digest(computed, sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_hub_signature: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    body = await request.body()

    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    # Prefer sha256 header if provided, else sha1 header.
    _verify_signature(body, x_hub_signature_256 or x_hub_signature, webhook_secret)

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if x_github_event != "push":
        # Hackathon-friendly: ignore other events.
        return {"status": "ignored", "reason": f"Unsupported event {x_github_event}"}

    repo = payload.get("repository") or {}
    clone_url = repo.get("clone_url") or repo.get("html_url")
    commit_id = payload.get("after") or ""

    if not clone_url:
        raise HTTPException(status_code=400, detail="Missing repository clone_url")

    logger.info("Received push webhook repo=%s commit=%s", clone_url, commit_id)

    # Run orchestrator (async) - for MVP we do it inline; for scale you’d queue it.
    result = await run_workflow(repo_url=clone_url, commit_sha=commit_id)
    return {"status": "ok", "result": result}
