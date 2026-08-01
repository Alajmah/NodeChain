"""Model Adapter — model-agnostic LLM interface.

Supports:
  - anthropic: Claude via Anthropic SDK
  - openai_compatible: Any OpenAI-compatible server (LM Studio, Ollama, vLLM, etc.)
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from pydantic import BaseModel


class ModelResponse(BaseModel):
    """Structured response from a model call."""

    content: str
    structured_output: dict[str, Any] | list[Any] | None = None
    model: str = ""
    usage: dict[str, int] = {}
    cost_usd: float = 0.0
    latency_ms: int = 0
    stop_reason: str = ""  # "stop", "length", "content_filter", etc.
    raw_output_size: int = 0  # bytes of raw model output before parsing


class ModelAdapter:
    """
    Model-agnostic adapter for LLM calls.

    Providers:
      - "anthropic": Claude via Anthropic SDK
      - "openai_compatible": Any OpenAI-compatible server (LM Studio, Ollama, vLLM)
    
    For local inference, use:
        ModelAdapter(provider="openai_compatible", base_url="http://192.0.2.1:1234/v1", model="qwen/qwen3-4b-2507")
    """

    def __init__(
        self,
        provider: str = "anthropic",
        model: str = "claude-sonnet-4-20250514",
        api_key: str | None = None,
        base_url: str | None = None,
        default_max_tokens: int = 4096,
    ) -> None:
        self.provider = provider
        self.model = model
        self.default_max_tokens = default_max_tokens
        self.base_url = base_url

        if provider == "anthropic":
            import anthropic
            key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            self._client = anthropic.Anthropic(api_key=key)
        elif provider == "openai_compatible":
            from openai import OpenAI
            url = base_url or os.environ.get(
                "OPENAI_BASE_URL", "http://192.0.2.1:1234/v1"
            )
            key = api_key or os.environ.get("OPENAI_API_KEY", "unused")
            self._client = OpenAI(base_url=url, api_key=key)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        output_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        """Synchronous model completion."""
        start = time.time()

        if self.provider == "anthropic":
            result = self._complete_anthropic(
                system_prompt, user_message, max_tokens, temperature, output_schema
            )
        elif self.provider == "openai_compatible":
            result = self._complete_openai(
                system_prompt, user_message, max_tokens, temperature, output_schema
            )
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

        elapsed_ms = int((time.time() - start) * 1000)
        result.latency_ms = elapsed_ms
        return result

    def _complete_anthropic(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None,
        temperature: float,
        output_schema: dict[str, Any] | None,
    ) -> ModelResponse:
        """Anthropic Claude completion."""
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.default_max_tokens,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }

        if output_schema:
            kwargs["tools"] = [
                {
                    "name": "structured_output",
                    "description": "Output structured data",
                    "input_schema": output_schema,
                }
            ]
            kwargs["tool_choice"] = {"type": "tool", "name": "structured_output"}

        response = self._client.messages.create(**kwargs)

        content = ""
        structured_output = None

        if output_schema and response.content:
            for block in response.content:
                if block.type == "tool_use":
                    structured_output = block.input
                    content = json.dumps(block.input, indent=2)
        elif response.content:
            for block in response.content:
                if hasattr(block, "text"):
                    content += block.text

        cost_usd = self._estimate_cost_anthropic(response.usage)

        return ModelResponse(
            content=content,
            structured_output=structured_output,
            model=response.model,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
            cost_usd=cost_usd,
        )

    def _complete_openai(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None,
        temperature: float,
        output_schema: dict[str, Any] | None,
    ) -> ModelResponse:
        """OpenAI-compatible completion (LM Studio, Ollama, vLLM, etc.)."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        # For structured output, append JSON instruction to system prompt
        if output_schema:
            json_instruction = (
                "\n\nIMPORTANT: You MUST respond with ONLY valid JSON matching this schema. "
                "No markdown code fences. No explanation. Just the JSON object:\n"
                + json.dumps(output_schema, indent=2)
            )
            messages[0]["content"] += json_instruction

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.default_max_tokens,
            "temperature": temperature,
        }

        response = self._client.chat.completions.create(**kwargs)

        content = response.choices[0].message.content or ""
        structured_output = None

        if output_schema and content:
            structured_output = self._extract_json(content)
            if structured_output:
                content = json.dumps(structured_output, indent=2)

        # Token usage
        usage = {}
        if response.usage:
            usage = {
                "input_tokens": response.usage.prompt_tokens or 0,
                "output_tokens": response.usage.completion_tokens or 0,
            }

        return ModelResponse(
            content=content,
            structured_output=structured_output,
            model=response.model or self.model,
            usage=usage,
            cost_usd=0.0,  # Local inference = free
        )

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | list[Any] | None:
        """Extract JSON from model output, handling markdown fences and prefixes."""
        # Try direct parse
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try removing markdown code fences
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try finding first { ... } block
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        # Try finding first [ ... ] block
        bracket_match = re.search(r"\[.*\]", text, re.DOTALL)
        if bracket_match:
            try:
                return json.loads(bracket_match.group())
            except json.JSONDecodeError:
                pass

        # Last resort: try to repair truncated JSON by closing open brackets
        try:
            repaired = text.strip()
            # Count open vs close brackets
            open_braces = repaired.count('{') - repaired.count('}')
            open_brackets = repaired.count('[') - repaired.count(']')
            if open_braces > 0 or open_brackets > 0:
                # Close any open strings first
                if repaired.count('"') % 2 != 0:
                    repaired += '"'
                repaired += ']' * max(0, open_brackets)
                repaired += '}' * max(0, open_braces)
                return json.loads(repaired)
        except (json.JSONDecodeError, ValueError):
            pass

        return None

    async def acomplete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        output_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        """Async model completion. Delegates to sync for now."""
        return self.complete(
            system_prompt=system_prompt,
            user_message=user_message,
            max_tokens=max_tokens,
            temperature=temperature,
            output_schema=output_schema,
        )

    def _estimate_cost_anthropic(self, usage: Any) -> float:
        """Estimate cost based on model and token usage (Anthropic only)."""
        input_tokens = getattr(usage, "input_tokens", 0)
        output_tokens = getattr(usage, "output_tokens", 0)

        costs = {
            "claude-sonnet-4-20250514": (3.0 / 1_000_000, 15.0 / 1_000_000),
            "claude-3-5-sonnet-20241022": (3.0 / 1_000_000, 15.0 / 1_000_000),
        }
        input_cost, output_cost = costs.get(
            self.model, (3.0 / 1_000_000, 15.0 / 1_000_000)
        )
        return (input_tokens * input_cost) + (output_tokens * output_cost)
