"""H0.4 static authority guard: exactly one ChainTrace.add_event call in all
production code, inside Orchestrator._record_trace_event.

The singular emission authority means the ONLY production call to
``.add_event(...)`` in ``src/nodechain/`` is inside
``Orchestrator._record_trace_event``. Any call outside that method — in
the orchestrator, controllers, TraceEmitter, recovery service, or anywhere
else — is a production bypass of the durable-first boundary.
"""

from __future__ import annotations

import ast
import pathlib


SRC_ROOT = pathlib.Path("src/nodechain")

#: The only method allowed to call .add_event in production code.
AUTHORITY_METHOD = "_record_trace_event"
AUTHORITY_CLASS = "Orchestrator"


def test_exactly_one_add_event_call_in_production() -> None:
    """The ONLY ``.add_event(...)`` call expression in ``src/nodechain/`` is
    inside ``Orchestrator._record_trace_event``.

    Scans every ``.py`` file under ``src/nodechain/`` for call expressions
    whose attribute is ``add_event``. The single permitted site is the
    authority method itself.
    """
    offenders: list[str] = []
    authority_found = False

    for py_file in SRC_ROOT.rglob("*.py"):
        src = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_event"):
                continue

            # Check whether this call is inside _record_trace_event
            rel_path = str(py_file).replace("\\", "/")
            if "orchestrator.py" in rel_path:
                # Find the enclosing function for this call
                enclosing = _find_enclosing_function(tree, node.lineno)
                if enclosing == AUTHORITY_METHOD:
                    authority_found = True
                    continue

            offenders.append(f"{py_file}:{node.lineno}")

    assert authority_found, (
        f"_record_trace_event's .add_event call not found — "
        f"the authority itself is missing"
    )
    assert not offenders, (
        f"found .add_event() calls outside {AUTHORITY_METHOD} in production code:\n"
        + "\n".join(f"  {o}" for o in offenders)
        + "\n— all production trace events must route through the singular authority"
    )


def _find_enclosing_function(tree: ast.AST, lineno: int) -> str | None:
    """Return the name of the function/method enclosing the given line."""
    best: str | None = None
    best_start = -1
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.lineno <= lineno:
            end = getattr(node, "end_lineno", None)
            if end is not None and lineno <= end:
                if node.lineno > best_start:
                    best_start = node.lineno
                    best = node.name
    return best
