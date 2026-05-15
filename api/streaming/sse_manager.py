import json
from typing import Any, Dict, Optional


def format_sse(data: Dict[str, Any], event: Optional[str] = None) -> str:
    """Format a Server-Sent Event payload.

    SSE frame format:
      event: <event-name>\n
      data: <json>\n
      \n
    We always JSON-encode the data payload.
    """

    payload = json.dumps(data, ensure_ascii=False)
    lines = []
    if event:
        lines.append(f"event: {event}")
    # SSE allows multiple data: lines; keep it simple.
    lines.append(f"data: {payload}")
    return "\n".join(lines) + "\n\n"
