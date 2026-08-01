"""Exit codes for NodeChain CLI commands.

Structured exit codes for scriptable operator workflows.
All CLI commands use these constants instead of raw numbers.
"""

# ── Common ──────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_NOT_FOUND = 2          # Run ID not found / unreadable state / file not found

# ── reconcile ───────────────────────────────────────────────────────
EXIT_RECONCILE_ERRORS = 1    # Hard reconciliation errors / lockfile drift
EXIT_RECONCILE_RECOVERY = 3  # Side effects in 'unknown' state (recovery needed)

# ── run ─────────────────────────────────────────────────────────────
EXIT_RUN_VALIDATION = 10     # Validation/governance failure
EXIT_RUN_PAUSED = 11         # Chain paused for human review
EXIT_RUN_FAILED = 12         # Chain execution failed

# ── inspect ─────────────────────────────────────────────────────────
EXIT_INSPECT_NOT_FOUND = 2   # Same as NOT_FOUND

# ── resume ──────────────────────────────────────────────────────────
EXIT_RESUME_NOT_RESUMABLE = 13  # Run is completed/not resumable
EXIT_RESUME_FAILED = 14         # Resume execution failed

# ── trust ───────────────────────────────────────────────────────────
EXIT_TRUST_VIOLATION = 15       # Trust invariant violation in strict mode

# -- audit-bundle (v1.6.1) ------------------------------------------
EXIT_VALIDATION = 10         # Bundle verification failed (alias)

# ── recover (v2.46.0) ───────────────────────────────────────────────
EXIT_RECOVERY_NOT_FOUND = 2      # Run not found (alias of NOT_FOUND)
EXIT_RECOVERY_NOT_ACTIONABLE = 16  # Run is terminal / no governed action applies
EXIT_RECOVERY_BLOCKED = 17         # Policy refused the requested action
