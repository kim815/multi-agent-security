import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    text: str
    raw: Dict[str, Any]


class IBMBobClient:
    """Tiny hackathon client wrapper.

    Assumptions (since hackathon + API varies):
    - Endpoint is provided via IBM_BOB_API_URL
    - API key via IBM_BOB_API_KEY
    - Accepts JSON: {"prompt": "...", "temperature": 0.2, "max_tokens": 300}
    - Returns {"text": "..."} or {"results": [{"generated_text": "..."}]}

    If not configured, caller can use deterministic fallback.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("IBM_BOB_API_KEY")
        self.api_url = os.getenv("IBM_BOB_API_URL")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_url)

    def generate_response(self, prompt: str, temperature: float = 0.2, max_tokens: int = 300) -> LLMResponse:
        if not self.is_configured():
            raise RuntimeError("IBM BOB client not configured (set IBM_BOB_API_URL and IBM_BOB_API_KEY)")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            resp = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            data: Dict[str, Any] = resp.json()
        except Exception as exc:
            logger.exception("IBM BOB API call failed")
            raise RuntimeError(f"IBM BOB API call failed: {exc}") from exc

        text = ""
        if isinstance(data.get("text"), str):
            text = data["text"]
        elif isinstance(data.get("results"), list) and data["results"]:
            text = data["results"][0].get("generated_text") or ""
        else:
            text = json.dumps(data)

        return LLMResponse(text=text, raw=data)
