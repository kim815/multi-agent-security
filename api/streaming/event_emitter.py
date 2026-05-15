import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, Optional

from .sse_manager import format_sse


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class SSEEventEmitter:
    """Async event emitter backed by an asyncio.Queue.

    - Producers call emit_* methods.
    - Consumer iterates `iter_sse()` and writes to StreamingResponse.

    Cancellation:
    - If the client disconnects, the StreamingResponse generator will be cancelled.
      We expose `cancel_event` so workflow can stop early if desired.
    """

    queue: "asyncio.Queue[str]"
    cancel_event: asyncio.Event

    @classmethod
    def create(cls) -> "SSEEventEmitter":
        return cls(queue=asyncio.Queue(), cancel_event=asyncio.Event())

    async def emit(self, payload: Dict[str, Any], event_name: Optional[str] = None) -> None:
        await self.queue.put(format_sse(payload, event=event_name))

    async def emit_agent_started(self, agent: str) -> None:
        await self.emit(
            {
                "event": "agent_status",
                "agent": agent,
                "status": "started",
                "timestamp": _utc_now_iso(),
            },
            event_name="agent_status",
        )

    async def emit_agent_completed(self, agent: str, data: Dict[str, Any]) -> None:
        await self.emit(
            {
                "event": "agent_status",
                "agent": agent,
                "status": "completed",
                "timestamp": _utc_now_iso(),
                "data": data,
            },
            event_name="agent_status",
        )

    async def emit_agent_failed(self, agent: str, message: str, details: str = "") -> None:
        await self.emit(
            {
                "event": "agent_status",
                "agent": agent,
                "status": "failed",
                "timestamp": _utc_now_iso(),
                "error": {"message": message, "details": details},
            },
            event_name="agent_status",
        )

    async def emit_workflow_completed(
        self,
        status: str,
        summary: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
        error: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload: Dict[str, Any] = {
            "event": "workflow_completed",
            "status": status,
            "timestamp": _utc_now_iso(),
        }
        if message:
            payload["message"] = message
        if summary is not None:
            payload["summary"] = summary
        if error is not None:
            payload["error"] = error
        await self.emit(payload, event_name="workflow_completed")

    async def close(self) -> None:
        """Signal the consumer to stop."""
        await self.queue.put("__CLOSE__")

    async def iter_sse(self, heartbeat_seconds: float = 15.0) -> AsyncIterator[str]:
        """Yield SSE frames as they become available.

        Includes periodic heartbeats so proxies don’t buffer forever.
        """

        while True:
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=heartbeat_seconds)
            except asyncio.TimeoutError:
                # Comment line heartbeat
                yield ": keep-alive\n\n"
                continue

            if item == "__CLOSE__":
                break

            yield item
