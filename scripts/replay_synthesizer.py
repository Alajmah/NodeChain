#!/usr/bin/env python
"""
v2.68 Evidence Synthesizer — isolated replay harness.

Replays the EXACT prompt the Evidence Synthesizer node would send, against the
frozen QualifiedSourceSet from run 62008aa6, with full instrumentation. Captures
the raw model response so we can diagnose WHY synthesis produced 0 claims.

This bypasses the orchestrator entirely — it constructs the same prompt the node
builds (per src/nodechain/nodes/evidence_synthesizer.py lines 122-274) and fires
one completion through the same ModelAdapter the chain uses.

Usage:
    # Use the same env the failed run used
    export OPENAI_BASE_URL=http://192.0.2.1:1234/v1
    export OPENAI_API_KEY=unused
    python scripts/replay_synthesizer.py --model google/gemma-4-12b
    python scripts/replay_synthesizer.py --model qwen/qwen3.5-27b --label qwen27b

Outputs:
    data/v2.68_replay/replay_<label>_<timestamp>.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
import traceback
from pathlib import Path

# Ensure src is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def build_synthesizer_prompt(frozen_path: str) -> tuple[str, str, list[dict], dict]:
    """
    Reconstruct the EXACT prompt the Evidence Synthesizer node builds.

    Mirrors src/nodechain/nodes/evidence_synthesizer.py execute() logic:
      1. Pull qualified_sources + all_sources from frozen state
      2. Cross-reference path (qualified refs match source ids) -> enrich
      3. Filter to sources WITH abstracts
      4. Sort by quality_score desc
      5. Take top 8
      6. Apply alias map (S1, S2, ...) for the model
      7. Build user_message + system_prompt

    Returns (system_prompt, user_message, aliased_sources, alias_map).
    """
    # Import the node's own constants — we want the EXACT system prompt, not a copy.
    from nodechain.nodes.evidence_synthesizer import (
        SYNTHESIZER_SYSTEM_PROMPT,
        OUTPUT_SCHEMA,
    )

    with open(frozen_path) as f:
        frozen = json.load(f)

    qualified = frozen.get("quality_evaluator_output", {}).get("qualified_sources", [])
    all_sources = frozen["qualified_source_set"]

    # Cross-reference path (lines 134-160 of evidence_synthesizer.py)
    src_ids = {s.get("source_id", "") for s in all_sources if s}
    qs_refs = {q.get("source_ref", "") for q in qualified if isinstance(q, dict)}
    has_matches = bool(src_ids & qs_refs)

    sources_for_model = []
    if has_matches and qualified:
        source_map = {s.get("source_id", ""): s for s in all_sources if s}
        for qs in qualified:
            if qs is None or not isinstance(qs, dict):
                continue
            if not qs.get("included", True):
                continue
            ref = qs.get("source_ref", "") or qs.get("source_id", "")
            full = source_map.get(ref, {}) or {}
            sources_for_model.append({
                "source_ref": ref,
                "quality_score": qs.get("quality_score", 0),
                "title": full.get("title", ""),
                "authors": full.get("authors", []) or [],
                "venue": full.get("venue", "") or "",
                "year": full.get("publication_date", "") or "",
                "citation_count": full.get("citation_count", 0) or 0,
                "abstract": (full.get("abstract", "") or "")[:500],
            })
    elif all_sources:
        # Direct path fallback
        for s in all_sources:
            if s is None:
                continue
            sources_for_model.append({
                "source_ref": s.get("source_id", ""),
                "quality_score": s.get("credibility_signals", {}).get("overall_score", 0.5) if isinstance(s.get("credibility_signals"), dict) else 0.5,
                "title": s.get("title", "") or "",
                "authors": s.get("authors", []) or [],
                "venue": s.get("venue", "") or "",
                "year": s.get("publication_date", "") or s.get("year", "") or "",
                "citation_count": s.get("citation_count", 0) or 0,
                "abstract": (s.get("abstract", "") or "")[:500],
            })

    # Top-8 by quality, with abstracts only (lines 206-210)
    sources_with_abstracts = [s for s in sources_for_model if s.get("abstract")]
    sources_with_abstracts.sort(key=lambda s: s.get("quality_score", 0), reverse=True)
    sources_with_content = sources_with_abstracts[:8]
    if not sources_with_content:
        sources_with_content = sources_for_model[:5]

    # Alias map (lines 245-258)
    alias_map: dict[str, str] = {}
    aliased_sources: list[dict] = []
    for i, s in enumerate(sources_with_content, start=1):
        alias = f"S{i}"
        real_ref = s.get("source_ref", "")
        alias_map[alias] = real_ref
        aliased = {**s, "source_ref": alias}
        aliased_sources.append(aliased)

    allowed_ids = sorted(set(alias_map.keys()))

    user_message = (
        f"Synthesize evidence from these {len(aliased_sources)} sources. "
        f"Extract specific verifiable claims with citations.\n\n"
        f"IMPORTANT: You MUST cite sources using ONLY these IDs: {allowed_ids}. "
        f"Do NOT invent or modify source IDs.\n\n"
        f"{json.dumps(aliased_sources, indent=2)}"
    )

    return SYNTHESIZER_SYSTEM_PROMPT, user_message, aliased_sources, alias_map


def run_replay(model: str, label: str, frozen_path: str, base_url: str) -> dict:
    """Fire one completion with full instrumentation."""
    from nodechain.adapters.model_adapter import ModelAdapter
    from nodechain.nodes.evidence_synthesizer import OUTPUT_SCHEMA

    system_prompt, user_message, aliased_sources, alias_map = build_synthesizer_prompt(frozen_path)

    # Build adapter the same way run.py does (openai_compatible path)
    adapter = ModelAdapter(
        provider="openai_compatible",
        model=model,
        api_key=os.environ.get("OPENAI_API_KEY", "unused"),
        base_url=base_url,
    )

    instrumented: dict = {
        "label": label,
        "model_requested": model,
        "base_url": base_url,
        "frozen_run_id": "62008aa6-4133-4423-a033-8e99268a1526",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "prompt_stats": {
            "sources_to_model": len(aliased_sources),
            "system_prompt_chars": len(system_prompt),
            "user_message_chars": len(user_message),
            "total_prompt_chars": len(system_prompt) + len(user_message),
            "schema_appended_chars": len(json.dumps(OUTPUT_SCHEMA, indent=2)),
            "alias_map": alias_map,
        },
    }

    print(f"--- replay '{label}' | model={model} ---")
    print(f"    sources to model: {len(aliased_sources)}")
    print(f"    total prompt chars: {instrumented['prompt_stats']['total_prompt_chars']:,}")
    print(f"    (schema adds ~{instrumented['prompt_stats']['schema_appended_chars']:,} chars via ModelAdapter)")
    print(f"    firing completion...")

    t0 = time.time()
    error_trace = None
    response = None
    try:
        # Reproduce the EXACT call signature the node uses (lines 261-274)
        response = adapter.complete(
            system_prompt=system_prompt,
            user_message=user_message,
            output_schema=OUTPUT_SCHEMA,
            temperature=0.3,
            max_tokens=10240,
        )
    except Exception as e:
        error_trace = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        print(f"    EXCEPTION: {type(e).__name__}: {e}")

    elapsed = time.time() - t0

    instrumented["wall_clock_seconds"] = round(elapsed, 2)

    if response is not None:
        instrumented["model_response"] = {
            "content_chars": len(response.content or ""),
            "content_first_500": (response.content or "")[:500],
            "content_last_500": (response.content or "")[-500:] if response.content else "",
            "structured_output_present": response.structured_output is not None,
            "structured_output_claims_count": (
                len(response.structured_output.get("claims", []))
                if isinstance(response.structured_output, dict)
                else None
            ),
            "structured_output_preview": (
                json.dumps(response.structured_output, indent=2)[:800]
                if response.structured_output else None
            ),
            "model_returned": response.model,
            "usage": response.usage,
            "latency_ms": response.latency_ms,
            "stop_reason": response.stop_reason,
            "raw_output_size": response.raw_output_size,
            "cost_usd": response.cost_usd,
        }
        print(f"    content_chars: {instrumented['model_response']['content_chars']:,}")
        print(f"    structured_output_present: {instrumented['model_response']['structured_output_present']}")
        print(f"    structured claims: {instrumented['model_response']['structured_output_claims_count']}")
        print(f"    stop_reason: {instrumented['model_response']['stop_reason']}")
        print(f"    usage: {instrumented['model_response']['usage']}")
        print(f"    latency_ms: {instrumented['model_response']['latency_ms']}")

        # Diagnosis classification
        r = instrumented["model_response"]
        if r["content_chars"] == 0:
            instrumented["diagnosis"] = "EMPTY_OUTPUT"
            instrumented["diagnosis_note"] = "Model returned empty content. Likely token limit, generation stall, or adapter shape mismatch. NOT a JSON parse problem."
        elif not r["structured_output_present"]:
            instrumented["diagnosis"] = "JSON_PARSE_FAILURE"
            instrumented["diagnosis_note"] = "Model returned content but ModelAdapter could not extract JSON. Inspect content_first_500/content_last_500 for markdown fences, partial JSON, or refusal."
        elif r["structured_output_claims_count"] == 0:
            instrumented["diagnosis"] = "ZERO_CLAIMS_DESPITE_VALID_JSON"
            instrumented["diagnosis_note"] = "Model produced valid JSON but with empty claims[]. This is a model-behavior/prompt issue, not a parse issue."
        else:
            instrumented["diagnosis"] = "SUCCESS"
            instrumented["diagnosis_note"] = f"Model produced {r['structured_output_claims_count']} claims. Inspect for citation validity."
        print(f"    >>> DIAGNOSIS: {instrumented['diagnosis']}")
    else:
        instrumented["exception"] = error_trace
        instrumented["diagnosis"] = "ADAPTER_EXCEPTION"
        instrumented["diagnosis_note"] = "ModelAdapter.complete() raised. Inspect exception trace."

    return instrumented


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="Model slug (e.g. google/gemma-4-12b)")
    ap.add_argument("--label", default=None, help="Label for the output file (defaults to model slug)")
    ap.add_argument("--frozen", default="data/v2.68_replay/frozen_synthesizer_input.json")
    ap.add_argument("--base-url", default=None, help="Override OPENAI_BASE_URL")
    args = ap.parse_args()

    base_url = args.base_url or os.environ.get("OPENAI_BASE_URL", "http://192.0.2.1:1234/v1")
    label = args.label or args.model.replace("/", "_")

    if not Path(args.frozen).exists():
        print(f"ERROR: frozen input not found at {args.frozen}", file=sys.stderr)
        return 2

    result = run_replay(args.model, label, args.frozen, base_url)

    out_dir = Path("data/v2.68_replay")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = out_dir / f"replay_{label}_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n=== saved {out_path} ===")
    print(f"    diagnosis: {result.get('diagnosis', '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
