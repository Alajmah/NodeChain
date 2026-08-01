"""LIM-Aware Model Adapter — routes through Local Inference Managers.

Uses LIM's catalog API to:
  - Query model capabilities (context_length, is_loaded, fitness_score)
  - Size prompts to fit within the active context window
  - Route through LIM's OpenAI-compatible proxy with health monitoring
  - Pick different models for different task types (fast vs reasoning)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Default LIM endpoint
DEFAULT_LIM_URL = "http://localhost:8766"

# Import shared ModelResponse from the base adapter
from nodechain.adapters.model_adapter import ModelResponse  # noqa: E402


class ModelInfo(BaseModel):
    """Model capabilities from LIM catalog."""

    model_id: str
    context_length: int = 4096
    active_context: int = 4096
    is_loaded: bool = False
    quantization: str = "unknown"
    size_gb: float = 0.0
    fitness_score: float = 0.0
    supports_json: bool = True
    supports_tools: bool = False
    supports_thinking: bool = False
    gpu_kv_cache: bool = False
    flash_attention: bool = False
    endpoint_url: str = ""


class LIMModelAdapter:
    """
    Model adapter that routes through LIM (Local Inference Managers).

    Features:
      - Queries LIM catalog for model capabilities
      - Sizes prompts to fit within active context window
      - Supports model routing by task type (fast, reasoning, auto)
      - Handles circuit breaker 503s gracefully
      - Truncates source data when approaching context limits
    """

    def __init__(
        self,
        lim_url: str | None = None,
        model: str = "auto",
        default_max_tokens: int = 4096,
    ) -> None:
        self.lim_url = (lim_url or os.environ.get("LIM_BASE_URL", DEFAULT_LIM_URL)).rstrip("/")
        self.model = model
        self.default_max_tokens = default_max_tokens
        self._catalog_cache: dict[str, ModelInfo] = {}
        self._catalog_fetched_at: float = 0.0
        self._cache_ttl: float = 30.0  # Refresh catalog every 30s

    # ── Catalog ──────────────────────────────────────────────

    def _fetch_catalog(self) -> dict[str, ModelInfo]:
        """Fetch model catalog from LIM (cached for _cache_ttl seconds)."""
        now = time.time()
        if self._catalog_cache and (now - self._catalog_fetched_at) < self._cache_ttl:
            return self._catalog_cache

        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.get(f"{self.lim_url}/api/catalog")
                r.raise_for_status()
                data = r.json()

            catalog: dict[str, ModelInfo] = {}
            for m in data.get("models", []):
                cfg = m.get("instance_config") or {}
                caps = m.get("capabilities") or {}
                mid = m.get("model_id", "")
                catalog[mid] = ModelInfo(
                    model_id=mid,
                    context_length=m.get("context_length", 4096),
                    active_context=cfg.get("context_length", m.get("context_length", 4096)),
                    is_loaded=m.get("is_loaded", False),
                    quantization=m.get("quantization", "unknown"),
                    size_gb=m.get("size_gb", 0.0),
                    fitness_score=m.get("fitness_score", 0.0),
                    supports_json=caps.get("json_mode", True),
                    supports_tools=caps.get("tools", False),
                    supports_thinking=caps.get("thinking", False),
                    gpu_kv_cache=cfg.get("offload_kv_cache_to_gpu", False),
                    flash_attention=cfg.get("flash_attention", False),
                    endpoint_url=m.get("endpoint_url", ""),
                )

            self._catalog_cache = catalog
            self._catalog_fetched_at = now
            logger.info("LIM catalog: %d models, %d loaded",
                        len(catalog), sum(1 for m in catalog.values() if m.is_loaded))
            return catalog

        except Exception as e:
            logger.warning("Failed to fetch LIM catalog: %s", e)
            return self._catalog_cache

    def get_model_info(self, model_id: str | None = None) -> ModelInfo | None:
        """Get info for a specific model."""
        catalog = self._fetch_catalog()
        mid = model_id or self.model
        return catalog.get(mid)

    def get_loaded_models(self) -> list[ModelInfo]:
        """Get all currently loaded models."""
        catalog = self._fetch_catalog()
        return [m for m in catalog.values() if m.is_loaded]

    def get_effective_context(self, model_id: str | None = None) -> int:
        """Get the active context window for a model."""
        info = self.get_model_info(model_id)
        if info:
            return info.active_context
        return 4096  # Safe default

    def pick_model(self, task_type: str = "auto") -> str:
        """Pick the best model for a task type.

        task_type:
          - "auto" — let LIM route (returns "auto")
          - "fast" — smallest loaded model (speed)
          - "reasoning" — biggest loaded model with thinking support
          - "json" — any loaded model with best JSON reliability
          - a specific model_id — return as-is
        """
        if task_type == "auto":
            return "auto"

        # If it looks like a specific model ID (contains /), return as-is
        if "/" in task_type:
            return task_type

        loaded = self.get_loaded_models()
        if not loaded:
            logger.warning("No loaded models found, falling back to 'auto'")
            return "auto"

        if task_type == "fast":
            return min(loaded, key=lambda m: m.size_gb).model_id

        if task_type == "reasoning":
            thinkers = [m for m in loaded if m.supports_thinking]
            if thinkers:
                return max(thinkers, key=lambda m: m.size_gb).model_id
            return max(loaded, key=lambda m: m.fitness_score).model_id

        if task_type == "json":
            return max(loaded, key=lambda m: m.fitness_score).model_id

        # Default: highest fitness
        return max(loaded, key=lambda m: m.fitness_score).model_id

    # ── Prompt Sizing ────────────────────────────────────────

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token estimate (~4 chars per token for English)."""
        return max(1, len(text) // 4)

    def truncate_for_context(
        self,
        prompt: str,
        model_id: str | None = None,
        max_output_tokens: int = 4096,
        safety_margin: int = 512,
    ) -> str:
        """Truncate prompt to fit within model's active context window.

        Leaves room for: prompt + max_output_tokens + safety_margin.
        """
        ctx = self.get_effective_context(model_id)
        budget = ctx - max_output_tokens - safety_margin

        if budget <= 0:
            logger.warning("Context budget <= 0 for model %s (ctx=%d, output=%d, margin=%d)",
                           model_id, ctx, max_output_tokens, safety_margin)
            budget = ctx // 2  # Desperate fallback

        prompt_tokens = self.estimate_tokens(prompt)
        if prompt_tokens <= budget:
            return prompt

        # Truncate to budget (in chars)
        max_chars = budget * 4
        truncated = prompt[:max_chars]
        # Try to cut at last complete JSON object or sentence
        for cut_char in ["}\n", ".\n", "\n\n"]:
            idx = truncated.rfind(cut_char)
            if idx > max_chars // 2:
                truncated = truncated[:idx + len(cut_char)]
                break

        logger.info("Truncated prompt: %d -> %d estimated tokens (budget=%d, ctx=%d)",
                     prompt_tokens, self.estimate_tokens(truncated), budget, ctx)
        return truncated

    # ── Completion ───────────────────────────────────────────

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        output_schema: dict[str, Any] | None = None,
        task_type: str = "auto",
    ) -> ModelResponse:
        """Synchronous model completion through LIM."""
        start = time.time()

        # Resolve model
        model_id = self.model if task_type == "auto" else self.pick_model(task_type)
        output_tokens = max_tokens or self.default_max_tokens

        # Build messages
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        # Add JSON instruction for structured output
        if output_schema:
            json_instruction = (
                "\n\nIMPORTANT: You MUST respond with ONLY valid JSON matching this schema. "
                "No markdown code fences. No explanation. Just the JSON object:\n"
                + json.dumps(output_schema, indent=2)
            )
            messages[0]["content"] += json_instruction

        # Serialize and truncate for context
        full_prompt = json.dumps(messages)
        if model_id != "auto":
            truncated = self.truncate_for_context(full_prompt, model_id, output_tokens)
            if truncated != full_prompt:
                # Re-parse truncated messages (best effort)
                try:
                    messages = json.loads(truncated)
                except json.JSONDecodeError:
                    # Just truncate the user message
                    budget = self.get_effective_context(model_id) - output_tokens - 512
                    user_budget = (budget * 4) - len(system_prompt) - 200
                    if user_budget > 200:
                        messages[1]["content"] = user_message[:user_budget]
                    logger.info("Truncated user message for context")

        # Call LIM
        try:
            result = self._call_lim(model_id, messages, output_tokens, temperature)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 503:
                # Circuit breaker open — try fallback
                logger.warning("Circuit breaker open for %s, trying fallback", model_id)
                fallback = self._pick_fallback(model_id)
                if fallback:
                    result = self._call_lim(fallback, messages, output_tokens, temperature)
                else:
                    raise
            else:
                raise

        elapsed_ms = int((time.time() - start) * 1000)
        result.latency_ms = elapsed_ms
        return result

    def _call_lim(
        self,
        model_id: str,
        messages: list[dict],
        max_tokens: int,
        temperature: float,
    ) -> ModelResponse:
        """Make the API call. Bypasses LIM proxy for performance,
        hitting LM Studio directly. Uses LIM only for catalog/health.
        """
        # Get the real endpoint from LIM catalog
        info = self.get_model_info(model_id)
        direct_url = info.endpoint_url if info else None

        # Fall back to LIM proxy if no direct URL found
        url = direct_url or f"{self.lim_url}/v1/chat/completions"
        if url and not url.endswith("/chat/completions"):
            url = f"{url}/chat/completions"

        with httpx.Client(timeout=300.0) as client:
            r = client.post(
                url,
                json={
                    "model": model_id,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )
            r.raise_for_status()
            data = r.json()

        content = data["choices"][0]["message"]["content"] or ""
        model_used = data.get("model", model_id)
        structured_output = None

        # Capture stop reason and raw output size before any repair
        stop_reason = data["choices"][0].get("finish_reason", "unknown")
        raw_output_size = len(content.encode("utf-8"))

        # Try to extract structured JSON from content
        # Check if output looks like JSON
        stripped = content.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            structured_output = self._extract_json(content)
            if structured_output:
                content = json.dumps(structured_output, indent=2)

        # If we expected JSON but didn't get it, try one more repair pass
        if structured_output is None and ("{\"" in stripped or "[\"" in stripped):
            structured_output = self._repair_json(stripped)
            if structured_output:
                content = json.dumps(structured_output, indent=2)

        usage = {}
        if data.get("usage"):
            usage = {
                "input_tokens": data["usage"].get("prompt_tokens", 0),
                "output_tokens": data["usage"].get("completion_tokens", 0),
            }

        return ModelResponse(
            content=content,
            structured_output=structured_output,
            model=model_used,
            usage=usage,
            cost_usd=0.0,  # Local inference = free
            stop_reason=stop_reason,
            raw_output_size=raw_output_size,
        )

    def _pick_fallback(self, failed_model: str) -> str | None:
        """Pick a fallback model when circuit breaker is open."""
        loaded = self.get_loaded_models()
        alternatives = [m for m in loaded if m.model_id != failed_model]
        if alternatives:
            return max(alternatives, key=lambda m: m.fitness_score).model_id
        return None

    async def acomplete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        output_schema: dict[str, Any] | None = None,
        task_type: str = "auto",
    ) -> ModelResponse:
        """Async completion — delegates to sync."""
        return self.complete(
            system_prompt=system_prompt,
            user_message=user_message,
            max_tokens=max_tokens,
            temperature=temperature,
            output_schema=output_schema,
            task_type=task_type,
        )

    # ── JSON Extraction ──────────────────────────────────────

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | list[Any] | None:
        """Extract JSON from model output, with repair for common LLM errors."""
        text = text.strip()

        # Direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Markdown code fences
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # { ... } block
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        # [ ... ] block
        bracket_match = re.search(r"\[.*\]", text, re.DOTALL)
        if bracket_match:
            try:
                return json.loads(bracket_match.group())
            except json.JSONDecodeError:
                pass

        # JSON repair: trailing commas, unclosed strings/brackets
        candidates = [text]
        fence = fence_match.group(1).strip() if fence_match else None
        if fence:
            candidates.append(fence)
        brace = brace_match.group() if brace_match else None
        if brace:
            candidates.append(brace)

        for candidate in candidates:
            repaired = LIMModelAdapter._repair_json(candidate)
            if repaired is not None:
                return repaired

        return None

    @staticmethod
    def _repair_json(text: str) -> dict[str, Any] | list[Any] | None:
        """Attempt to repair common JSON errors from LLM output.
        Handles: trailing commas, unclosed strings, missing closing brackets.
        """
        import re as _re

        # Step 1: Remove trailing commas before ] or }
        # Matches: , (with optional whitespace) followed by ] or }
        repaired = _re.sub(r',\s*([\]\\}])', r'\1', text)

        # Step 2: Try parse
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            pass

        # Step 3: Fix unclosed strings — add closing quote if odd count
        # But only if the last char is not already a quote or bracket
        if repaired.count('"') % 2 != 0:
            # Find the last unclosed string and close it
            repaired += '"'
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            pass

        # Step 3b: More aggressive string fix — replace broken string values
        # Pattern: "key": "value_with_no_closing_quote followed by , or } or ]
        repaired = _re.sub(r':\s*"([^"]*?)$', r': "\1"', repaired)
        repaired = _re.sub(r':\s*"([^"]*?)([\]\\}])', r': "\1"\2', repaired)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            pass

        # Step 4: Close open brackets/braces
        open_brackets = repaired.count('[') - repaired.count(']')
        open_braces = repaired.count('{') - repaired.count('}')
        if open_brackets > 0 or open_braces > 0:
            repaired += ']' * max(0, open_brackets)
            repaired += '}' * max(0, open_braces)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            pass

        # Step 5: More aggressive — strip everything after last valid closing
        # Find the last } or ] and try to parse up to that point
        for i in range(len(repaired) - 1, -1, -1):
            if repaired[i] in ('}', ']'):
                try:
                    return json.loads(repaired[:i+1])
                except json.JSONDecodeError:
                    continue

        return None

        return None
