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
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")

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

        text = (resp.choices[0].message.content or "").strip() if resp.choices else ""
        raw: Dict[str, Any] = resp.model_dump()  # type: ignore[no-any-return]
        return LLMResponse(text=text, raw=raw)
