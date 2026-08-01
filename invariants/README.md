# NodeChain Invariants Ledger

Append-only, globally numbered, never deleted. Referenced by plan files and tests by ID.

## Rules

- **Never renumber.** IDs are permanent. `INV-001` is always `INV-001`.
- **Never delete.** Superseded invariants are marked `REPLACED` with a `Superseded_by` cross-reference.
- **Append only.** New invariants get the next sequential number.
- **Plans reference by ID.** Implementation plans cite `INV-007`, they do not restate the invariant.
- **Tests reference by ID.** Test names or docstrings carry the invariant: `test_inv_007_capsule_commits_before_started`.
- **Enforcement is explicit.** Each invariant records its primary enforcement mechanism (`db_constraint`, `runtime_guard`, or `both`) and defense-in-depth layers.

## Status values

| Status | Meaning |
|---|---|
| `ACTIVE` | Currently enforced and load-bearing. |
| `REPLACED` | Superseded by a later invariant. Cross-referenced via `Superseded_by`. |
| `DEPRECATED` | No longer load-bearing but retained for historical context. |

## Files

| File | Scope |
|---|---|
| `v3.5.md` | Side-effect retry-authorized execution (INV-001 … INV-022) |

## Future files

Future releases append new files (`v3.6.md`, etc.) while retaining the global numbering namespace.
