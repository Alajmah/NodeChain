.PHONY: ci ci-core ci-blocking ci-fast ci-recovery ci-trust ci-shard ci-shard-1 ci-shard-3 ci-lint ci-smoke ci-package ci-windows install test

# NodeChain — local/CI verification parity (v2.48.0)
# These targets mirror the GitHub Actions CI jobs so "verified locally"
# and "verified in CI" use the same commands.

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

# Fast unit + governance tests (excludes slow sandbox/privileged/integration files)
ci-fast:
	$(PYTHON) -m pytest tests/ -q --tb=short \
		--ignore=tests/test_seccomp_integration.py \
		--ignore=tests/test_seccomp_consolidation.py \
		--ignore=tests/test_seccomp_productization.py \
		--ignore=tests/test_cgroup_behavior.py \
		--ignore=tests/test_cgroup_profile.py \
		--ignore=tests/test_pid_namespace.py \
		--ignore=tests/test_pid_namespace_procfs.py \
		--ignore=tests/test_mount_confinement.py \
		--ignore=tests/test_namespace_confinement.py \
		--ignore=tests/test_mount_namespace.py \
		--ignore=tests/test_mount_namespace_reporting.py \
		--ignore=tests/test_namespace_policy.py \
		--ignore=tests/test_namespace_reporting.py \
		--ignore=tests/test_network_hardening.py \
		--ignore=tests/test_subprocess_enforcement.py \
		--ignore=tests/test_subprocess_async.py \
		--ignore=tests/test_subprocess_runner.py \
		--ignore=tests/test_sandbox_demo.py \
		--ignore=tests/test_cwd_temp_isolation.py \
		--ignore=tests/test_hostile_network_cert.py \
		--ignore=tests/test_adversarial_remote.py \
		--ignore=tests/test_workflow_recovery_integration.py \
		--ignore=tests/test_mount_confinement_compat.py \
		--ignore=tests/test_mount_confinement_policy.py \
		--ignore=tests/test_preset_e2e.py \
		--ignore=tests/test_preset_wiring.py \
		--ignore=tests/test_checkpoint_commit_ordering.py \
		--ignore=tests/test_checkpoint_journal.py \
		--ignore=tests/test_checkpoint_semantic.py \
		--ignore=tests/test_checkpoint_signer_enforcement.py \
		--ignore=tests/test_checkpoint_crash_matrix.py \
		--ignore=tests/test_dashboard_health.py \
		--ignore=tests/test_dashboard_live_data.py \
		--ignore=tests/test_memory_dashboard.py \
		--ignore=tests/test_graph_cli_parity.py \
		--ignore=tests/test_chain_orchestrator.py \
		--ignore=tests/test_evaluation_suite_lifecycle.py

# Orchestrator + recovery console + budget tests
ci-recovery:
	$(PYTHON) -m pytest \
		tests/test_chain_orchestrator.py \
		tests/test_recovery_snapshot.py \
		tests/test_recovery_classifier.py \
		tests/test_recovery_service_read.py \
		tests/test_recovery_apply_action.py \
		tests/test_recovery_delegate_factory.py \
		tests/test_operator_action_policy.py \
		tests/test_operator_action_log.py \
		tests/test_operator_trace_events.py \
		tests/test_operator_recovery_console.py \
		tests/test_route_fallback.py \
		tests/test_budget_pause.py \
		tests/test_recover_cli_read.py \
		tests/test_recover_cli_actions.py \
		tests/test_review_resume.py \
		tests/test_regression_wiring_bugs.py \
		-q --tb=short

# Trust + collector + dashboard tests
ci-trust:
	$(PYTHON) -m pytest \
		tests/test_trust.py \
		tests/test_trust_resolver.py \
		tests/test_trust_ci_gates.py \
		tests/test_registry_consumption.py \
		tests/test_collector_existence_semantics.py \
		tests/test_dashboard_recovery.py \
		tests/test_dashboard_health.py \
		tests/test_review_dashboard_closure.py \
		tests/test_review_dashboard_wiring.py \
		-q --tb=short

# Run a specific slow shard (SHARD=1|2|3)
ci-shard:
	@echo "Run: make ci-shard SHARD=1  (checkpoint + loop)"
	@echo "     make ci-shard SHARD=2  (sandbox + security)"
	@echo "     make ci-shard SHARD=3  (proxmox + network + integration)"
	@exit 1

# Slow shard 1 (checkpoint + loop + evidence)
ci-shard-1:
	$(PYTHON) -m pytest \
		tests/test_checkpoint_commit_ordering.py \
		tests/test_checkpoint_journal.py \
		tests/test_checkpoint_semantic.py \
		tests/test_checkpoint_signer_enforcement.py \
		tests/test_checkpoint_crash_matrix.py \
		tests/test_checkpoint_signer.py \
		tests/test_loop_enforcement.py \
		tests/test_evidence_checkpoint.py \
		tests/test_branch_step_race.py \
		-q --tb=short

# Slow shard 3 (proxmox + network + integration)
ci-shard-3:
	$(PYTHON) -m pytest \
		tests/test_proxmox_api_idempotent.py \
		tests/test_proxmox_api_staging.py \
		tests/test_proxmox_api_task_actions.py \
		tests/test_proxmox_api_artifact.py \
		tests/test_proxmox_api_boot_id.py \
		tests/test_proxmox_api_rollback_chain.py \
		tests/test_proxmox_api_rollback_provenance.py \
		tests/test_proxmox_api_task_polling.py \
		tests/test_proxmox_negative_smokes.py \
		tests/test_network_hardening.py \
		tests/test_hostile_network_cert.py \
		tests/test_adversarial_remote.py \
		tests/test_workflow_recovery_integration.py \
		-q --tb=short

# All blocking CI jobs in sequence (matches CI workflow required checks)
ci-core: ci-fast ci-recovery ci-trust

ci-blocking: ci-lint ci-fast ci-recovery ci-trust ci-shard-1 ci-shard-3 ci-smoke ci-package

# Alias: full blocking CI surface
ci: ci-blocking

# Lint (matches CI lint job: py_compile + ruff)
ci-lint:
	$(PYTHON) -m py_compile $$(find src/nodechain -name '*.py')
	ruff check src/nodechain/ --select E9,F63,F7,F82 --no-cache --exit-zero

# CLI smoke tests (matches CI cli-smoke job)
ci-smoke:
	nodechain --version
	nodechain --help
	nodechain run --help
	nodechain inspect --help
	nodechain registry list
	nodechain trust --help
	nodechain recover --help
	nodechain recover list --help
	nodechain recover budget --help
	nodechain recover fallback --help
	nodechain recover profiles list

# Package build
ci-package:
	$(PYTHON) -m build --wheel

# Alias
test: ci-fast
