import asyncio
import logging
from typing import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from api.schemas.workflow_events import WorkflowTriggerRequest
from api.streaming.event_emitter import SSEEventEmitter
from orchestrator.workflow import run_workflow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workflow", tags=["workflow"])


@router.post("/trigger")
async def trigger_workflow(req: WorkflowTriggerRequest, request: Request) -> StreamingResponse:
    """Trigger a workflow run and stream real-time status updates (SSE).

    Note: SSE is typically a GET, but for hackathon/demo readiness we keep the
    request body in a POST and stream the response.
    """

    emitter = SSEEventEmitter.create()

    async def _run() -> None:
        try:
            await run_workflow(repo_url=req.repo_url, commit_sha="HEAD", emitter=emitter)
        except asyncio.CancelledError:
            logger.info("[sse] workflow task cancelled")
        except Exception as e:
            logger.exception("[sse] workflow failed")
            await emitter.emit_workflow_completed(
                status="failed",
                error={"message": "Workflow crashed", "details": str(e)},
            )
        finally:
            await emitter.close()

    task = asyncio.create_task(_run())

    async def event_stream() -> AsyncIterator[str]:
        try:
            async for frame in emitter.iter_sse():
                # Stop early if client disconnected
                if await request.is_disconnected():
                    emitter.cancel_event.set()
                    task.cancel()
                    break
                yield frame
        finally:
            emitter.cancel_event.set()
            if not task.done():
                task.cancel()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # nginx: disable response buffering
        },
    )
