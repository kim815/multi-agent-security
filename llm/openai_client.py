import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from openai import OpenAI

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    text: str
    raw: Dict[str, Any]


class OpenAIClient:
    """Minimal OpenAI chat client for hackathon usage.

    Env:
    - OPENAI_API_KEY (required)
    - OPENAI_MODEL (optional; default: gpt-4o-mini)

    Strict behavior: raise on any API error.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("OPENAI_API_KEY")
        # Model and optional base URL (for proxies or hosted endpoints)
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = os.getenv("OPENAI_BASE_URL")

        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")

        # Initialize the SDK client. If a custom base URL is provided (for proxying
        # or custom hosting), pass it to the constructor. The OpenAI SDK accepts
        # `base_url` (or falls back to its default).
        try:
            if self.base_url:
                logger.info("Using custom OpenAI base URL: %s", self.base_url)
                self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            else:
                self.client = OpenAI(api_key=self.api_key)
        except TypeError:
            # In case the installed SDK uses a different kwarg name, try api_base.
            if self.base_url:
                self.client = OpenAI(api_key=self.api_key, api_base=self.base_url)  # type: ignore[arg-type]
            else:
                self.client = OpenAI(api_key=self.api_key)

    def generate_response(self, prompt: str, temperature: float = 0.2, max_tokens: int = 200) -> LLMResponse:
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": "You are a secure dependency remediation AI."},
                    {"role": "user", "content": prompt},
                ],
            )
        except Exception as exc:
            logger.exception("OpenAI API call failed")
            raise

        # Parse text content (SDK response shape may vary).
        try:
            text = (resp.choices[0].message.content or "").strip() if getattr(resp, "choices", None) else ""
        except Exception:
            text = str(resp)

        # Turn the SDK response into a serializable raw dict when possible.
        raw: Dict[str, Any]
        try:
            raw = resp.model_dump()  # type: ignore[no-any-return]
        except Exception:
            try:
                raw = dict(resp)
            except Exception:
                raw = {"repr": repr(resp)}
        return LLMResponse(text=text, raw=raw)
