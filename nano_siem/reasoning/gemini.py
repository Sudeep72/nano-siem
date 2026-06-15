"""
reasoning/gemini.py — Gemini API Client

Thin async wrapper around the Google AI Studio REST API
(gemini-2.5-flash, free tier).

DESIGN CONSTRAINT (non-negotiable):
  Gemini NEVER performs detection.
  It only receives already-generated Alert objects and produces
  human-readable narratives, summaries, and recommendations.
  Raw events, Sigma rules, and ML scores are NEVER sent to Gemini
  except as context attached to a confirmed alert.

Usage:
    client = GeminiClient(api_key="your-key")
    response = await client.generate(prompt="Explain this alert...")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent"
)

# Rate limiting — free tier is 15 req/min
_RATE_LIMIT_CALLS = 14      # stay under 15
_RATE_LIMIT_WINDOW = 60.0   # seconds
_call_timestamps: list[float] = []


async def _rate_limit() -> None:
    """Simple sliding window rate limiter for free tier."""
    global _call_timestamps
    now = time.time()
    # Remove timestamps older than window
    _call_timestamps = [t for t in _call_timestamps if now - t < _RATE_LIMIT_WINDOW]
    if len(_call_timestamps) >= _RATE_LIMIT_CALLS:
        wait = _RATE_LIMIT_WINDOW - (now - _call_timestamps[0]) + 0.5
        if wait > 0:
            logger.info("Rate limit: waiting %.1fs before Gemini call", wait)
            await asyncio.sleep(wait)
    _call_timestamps.append(time.time())


@dataclass
class GeminiResponse:
    text: str
    model: str
    prompt_tokens: int
    output_tokens: int
    cached: bool = False


class GeminiClient:
    """
    Async Gemini API client.

    Get your free API key at: https://aistudio.google.com/app/apikey
    Set GEMINI_API_KEY env var or pass directly.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
        temperature: float = 0.3,
        max_output_tokens: int = 4096,
    ) -> None:
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self._model = model
        self._temperature = temperature
        self._max_output_tokens = max_output_tokens
        # Simple in-memory cache: prompt_hash → GeminiResponse
        self._cache: dict[str, GeminiResponse] = {}

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key != "YOUR_API_KEY_HERE")

    async def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        use_cache: bool = True,
    ) -> GeminiResponse:
        """
        Send a prompt to Gemini and return the response.

        Args:
            prompt:             The user prompt.
            system_instruction: Optional system-level instruction
                                (role definition, constraints).
            use_cache:          Return cached response for identical prompts.

        Returns:
            GeminiResponse with text and token counts.

        Raises:
            RuntimeError: If API key not configured or API call fails.
        """
        if not self.is_configured:
            raise RuntimeError(
                "Gemini API key not configured. "
                "Set GEMINI_API_KEY environment variable or pass api_key to GeminiClient. "
                "Get a free key at https://aistudio.google.com/app/apikey"
            )

        # Cache check
        cache_key = f"{system_instruction}||{prompt}"
        if use_cache and cache_key in self._cache:
            cached = self._cache[cache_key]
            return GeminiResponse(
                text=cached.text,
                model=cached.model,
                prompt_tokens=cached.prompt_tokens,
                output_tokens=cached.output_tokens,
                cached=True,
            )

        await _rate_limit()

        # Build request body
        body: dict = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self._temperature,
                "maxOutputTokens": self._max_output_tokens,
                "topP": 0.8,
            },
        }
        if system_instruction:
            body["system_instruction"] = {
                "parts": [{"text": system_instruction}]
            }

        url = f"{GEMINI_API_URL}?key={self._api_key}"

        # Async HTTP call using asyncio subprocess (no aiohttp dependency)
        import urllib.error
        import urllib.request

        def _call_api() -> dict:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                error_body = e.read().decode("utf-8")
                raise RuntimeError(f"Gemini API error {e.code}: {error_body}")

        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, _call_api)

        # Parse response
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raise RuntimeError(f"Unexpected Gemini response structure: {data}")

        usage = data.get("usageMetadata", {})
        response = GeminiResponse(
            text=text.strip(),
            model=self._model,
            prompt_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
        )

        if use_cache:
            self._cache[cache_key] = response

        logger.debug(
            "Gemini response: %d prompt tokens, %d output tokens",
            response.prompt_tokens, response.output_tokens,
        )
        return response

    def clear_cache(self) -> None:
        self._cache.clear()
