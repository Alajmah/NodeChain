#!/usr/bin/env python
"""
Permanent publication-tree hygiene guard.

Inspects the *committed* tree of a Git ref and rejects paths that must never
enter a clean publication of NodeChain. This is the authoritative gate: it
operates on `git ls-files`-equivalent data (the committed tree), not on the
working directory or `.gitignore`, because an ignore rule does not remove a
file that is already tracked.

Exit-code contract:

    0  no violations
    1  one or more violations (printed, sorted deterministically)
    2  Git, configuration, or execution error

Usage:

    python scripts/check_publication_tree.py [--ref REF]

`REF` defaults to `HEAD`.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import List, Tuple


# Forbidden top-level/local-state directories. Matched as path segments so that
# both the directory itself and anything nested under it are rejected.
FORBIDDEN_DIR_SEGMENTS: Tuple[str, ...] = (
    ".ouroboros",
    ".zcode",
    ".nodechain",
    ".benchmarks",
)

# Forbidden filename exact matches.
FORBIDDEN_EXACT_FILES: Tuple[str, ...] = (
    "sandbox_test_output.txt",
)

# Forbidden extensions, matched case-insensitively against the basename.
FORBIDDEN_EXTENSIONS: Tuple[str, ...] = (
    ".db",
    ".sqlite",
    ".sqlite3",
)

# Browser-style duplicate filename classifier, e.g. "Name (1).md", "a/b (2).py".
# A path is a violation when its final segment is "<base> (<digits>)<optional ext>"
# where the digits start at 1. Ordinary parenthesized filenames without the
# numeric duplicate suffix (for example "section_(notes).md") remain allowed.
DUPLICATE_NAME_RE = re.compile(r"(?:^|/)[^/]+ \([1-9][0-9]*\)(?:\.[^/]+)?$")


def _list_tree(ref: str) -> List[str]:
    """Return committed paths for *ref*, parsed from NUL-delimited git output."""
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--name-only", ref],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", errors="replace").strip()
        sys.stderr.write(
            "publication-tree guard: git ls-tree failed for ref "
            f"{ref!r} (exit {proc.returncode}): {msg}\n"
        )
        sys.exit(2)
    # ls-tree -z separates entries with NUL bytes; the trailing NUL produces a
    # final empty element that must be dropped.
    return [p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p]


def _classify(path: str) -> List[str]:
    """Return the list of rule names *path* violates (possibly empty)."""
    rules: List[str] = []
    parts = path.split("/")
    basename = parts[-1]

    for seg in FORBIDDEN_DIR_SEGMENTS:
        if seg in parts:
            rules.append(f"forbidden directory: {seg}/")

    lower_base = basename.lower()
    for ext in FORBIDDEN_EXTENSIONS:
        if lower_base.endswith(ext):
            rules.append(f"forbidden database extension: {ext}")
            break

    if basename in FORBIDDEN_EXACT_FILES:
        rules.append(f"forbidden stray artifact: {basename}")

    if DUPLICATE_NAME_RE.search(path):
        rules.append("browser-style duplicate filename: <name> (<n>)<ext>")

    return rules


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--ref",
        default=os.environ.get("PUBLICATION_REF", "HEAD"),
        help="Git ref to inspect (default: HEAD).",
    )
    args = parser.parse_args(argv)

    try:
        paths = _list_tree(args.ref)
    except SystemExit:
        # _list_tree already wrote a diagnostic and chose exit code 2.
        raise

    violations: List[Tuple[str, str]] = []
    for path in paths:
        for rule in _classify(path):
            violations.append((path, rule))

    if not violations:
        return 0

    for path, rule in sorted(violations):
        sys.stdout.write(f"{path}\t{rule}\n")
    sys.stdout.flush()
    return 1


if __name__ == "__main__":
    sys.exit(main())
