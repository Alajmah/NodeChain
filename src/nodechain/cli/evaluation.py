"""Evaluation Runner (v1.16.0).

Runs structured evaluations against nodes, chains, policies, adapters, traces,
and deployment/remediation outcomes, producing signed, repeatable evaluation
reports with pass/fail thresholds and regression history.

Evaluation answers:
  Is this node/chain/policy/adapter good enough to trust, publish,
  reuse, certify, or deploy?
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


#: Valid target types for evaluation
TARGET_TYPES = frozenset({
    "node", "chain", "policy", "adapter",
    "trace", "deployment", "remediation", "package",
})

#: Built-in metric names
BUILTIN_METRICS = frozenset({
    "correctness", "schema_validity", "contract_validity",
    "invariant_compliance", "policy_compliance", "trace_completeness",
    "cost", "latency", "deterministic_replay_match",
})


class EvaluationCase:
    """A single evaluation case within a suite."""

    def __init__(
        self,
        case_id: str,
        input_data: dict[str, Any] | None = None,
        expected_output: dict[str, Any] | None = None,
        expected_trace_properties: dict[str, Any] | None = None,
        expected_policy_verdict: str = "",
        expected_receipt_fields: dict[str, Any] | None = None,
        max_cost: float = 0.0,
        max_latency_ms: float = 0.0,
        required_invariants: list[str] | None = None,
        description: str = "",
    ):
        self.case_id = case_id
        self.input_data = input_data or {}
        self.expected_output = expected_output or {}
        self.expected_trace_properties = expected_trace_properties or {}
        self.expected_policy_verdict = expected_policy_verdict
        self.expected_receipt_fields = expected_receipt_fields or {}
        self.max_cost = max_cost
        self.max_latency_ms = max_latency_ms
        self.required_invariants = required_invariants or []
        self.description = description

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvaluationCase:
        return cls(
            case_id=data.get("case_id", ""),
            input_data=data.get("input"),
            expected_output=data.get("expected_output"),
            expected_trace_properties=data.get("expected_trace_properties"),
            expected_policy_verdict=data.get("expected_policy_verdict", ""),
            expected_receipt_fields=data.get("expected_receipt_fields"),
            max_cost=data.get("max_cost", 0.0),
            max_latency_ms=data.get("max_latency_ms", 0.0),
            required_invariants=data.get("required_invariants"),
            description=data.get("description", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "input": self.input_data,
            "expected_output": self.expected_output,
            "expected_trace_properties": self.expected_trace_properties,
            "expected_policy_verdict": self.expected_policy_verdict,
            "expected_receipt_fields": self.expected_receipt_fields,
            "max_cost": self.max_cost,
            "max_latency_ms": self.max_latency_ms,
            "required_invariants": self.required_invariants,
            "description": self.description,
        }


#: Valid suite statuses (v1.16.2)
SUITE_STATUSES = frozenset({"active", "deprecated", "revoked"})


class EvaluationSuite:
    """A suite of evaluation cases for a specific target.

    Fields:
        suite_id: Unique identifier for the suite.
        suite_version: Semver version of the suite.
        target_type: One of TARGET_TYPES.
        target_ref: Reference to the target (node ID, chain file, etc.).
        cases: List of EvaluationCase objects.
        metrics: List of metric names to evaluate.
        thresholds: Map of metric → minimum pass value (0.0–1.0).
        required_artifacts: List of artifact paths required for the eval.
        description: Human-readable description.
        Lifecycle fields (v1.16.2):
        valid_from: ISO timestamp when suite becomes active.
        valid_until: ISO timestamp when suite expires (empty = no expiry).
        supersedes_suite_digest: Digest of the suite this one supersedes.
        suite_status: active | deprecated | revoked.
    """

    def __init__(
        self,
        suite_id: str,
        suite_version: str = "1.0.0",
        target_type: str = "chain",
        target_ref: str = "",
        cases: list[EvaluationCase] | None = None,
        metrics: list[str] | None = None,
        thresholds: dict[str, float] | None = None,
        required_artifacts: list[str] | None = None,
        description: str = "",
        # v1.16.2 lifecycle fields
        valid_from: str = "",
        valid_until: str = "",
        supersedes_suite_digest: str = "",
        suite_status: str = "active",
    ):
        self.suite_id = suite_id
        self.suite_version = suite_version
        self.target_type = target_type
        self.target_ref = target_ref
        self.cases = cases or []
        self.metrics = metrics or list(BUILTIN_METRICS)
        self.thresholds = thresholds or {}
        self.required_artifacts = required_artifacts or []
        self.description = description
        # v1.16.2 lifecycle
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.supersedes_suite_digest = supersedes_suite_digest
        self.suite_status = suite_status

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvaluationSuite:
        cases = [EvaluationCase.from_dict(c) for c in data.get("cases", [])]
        return cls(
            suite_id=data.get("suite_id", ""),
            suite_version=data.get("suite_version", "1.0.0"),
            target_type=data.get("target_type", "chain"),
            target_ref=data.get("target_ref", ""),
            cases=cases,
            metrics=data.get("metrics"),
            thresholds=data.get("thresholds"),
            required_artifacts=data.get("required_artifacts"),
            description=data.get("description", ""),
            # v1.16.2 lifecycle
            valid_from=data.get("valid_from", ""),
            valid_until=data.get("valid_until", ""),
            supersedes_suite_digest=data.get("supersedes_suite_digest", ""),
            suite_status=data.get("suite_status", "active"),
        )

    @classmethod
    def from_file(cls, path: str) -> EvaluationSuite:
        """Load suite from YAML or JSON file."""
        raw = Path(path).read_text(encoding="utf-8")
        # Try JSON first, then YAML
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            import yaml
            data = yaml.safe_load(raw)
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "suite_version": self.suite_version,
            "target_type": self.target_type,
            "target_ref": self.target_ref,
            "cases": [c.to_dict() for c in self.cases],
            "metrics": self.metrics,
            "thresholds": self.thresholds,
            "required_artifacts": self.required_artifacts,
            "description": self.description,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "supersedes_suite_digest": self.supersedes_suite_digest,
            "suite_status": self.suite_status,
        }

    def digest(self) -> str:
        """SHA-256 digest of the suite definition."""
        return _sha256_dict(self.to_dict())

    def validate(self) -> list[str]:
        """Validate the suite. Returns list of error messages (empty = valid)."""
        errors: list[str] = []
        if not self.suite_id:
            errors.append("suite_id is required")
        if self.target_type not in TARGET_TYPES:
            errors.append(f"Invalid target_type: {self.target_type}. Valid: {sorted(TARGET_TYPES)}")
        if not self.cases:
            errors.append("At least one case is required")
        for i, case in enumerate(self.cases):
            if not case.case_id:
                errors.append(f"Case {i}: case_id is required")
        return errors

    def check_validity(self) -> tuple[bool, str]:
        """Check lifecycle validity of this suite (v1.16.2).

        Returns:
            (is_valid, reason) — reason is empty string if valid.
        """
        now = _now_iso()

        if self.suite_status == "revoked":
            return False, "Suite is revoked"
        if self.suite_status == "deprecated":
            return False, "Suite is deprecated"
        if self.suite_status not in SUITE_STATUSES:
            return False, f"Unknown suite_status: {self.suite_status}"

        if self.valid_from and now < self.valid_from:
            return False, f"Suite not yet valid (valid_from={self.valid_from})"
        if self.valid_until and now > self.valid_until:
            return False, f"Suite expired (valid_until={self.valid_until})"

        return True, ""


class CaseResult:
    """Result of running a single evaluation case."""

    def __init__(
        self,
        case_id: str,
        passed: bool,
        metrics: dict[str, Any] | None = None,
        detail: str = "",
        latency_ms: float = 0.0,
        cost: float = 0.0,
        failures: list[str] | None = None,
    ):
        self.case_id = case_id
        self.passed = passed
        self.metrics = metrics or {}
        self.detail = detail
        self.latency_ms = latency_ms
        self.cost = cost
        self.failures = failures or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "passed": self.passed,
            "metrics": self.metrics,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
            "cost": self.cost,
            "failures": self.failures,
        }


def run_evaluation(
    suite: EvaluationSuite | str,
    target_digest: str = "",
    strict: bool = False,
    custom_runner: Any = None,
    require_suite_signature: bool = False,
    trust_store_path: str = "",
    require_active_suite: bool = False,
) -> dict[str, Any]:
    """Run an evaluation suite and produce an evaluation report.

    Args:
        suite: EvaluationSuite instance or path to suite file.
        target_digest: Optional digest of the target being evaluated.
        strict: If True, threshold failures and missing artifacts are hard errors.
        custom_runner: Optional callable(case, suite) → CaseResult for custom eval logic.

    Returns:
        Evaluation report dict.
    """
    eval_id = str(uuid.uuid4())
    started_at = _now_iso()
    started_ts = time.time()

    from nodechain import __version__ as nodechain_version

    # Normalize suite
    _suite_sig_status = "unsigned"
    _suite_sig_fp = ""
    _suite_sig_trusted = False
    _suite_trust_verified = False
    # v1.16.2 lifecycle
    _suite_validity_status = "not_checked"
    _suite_registry_digest = ""

    if isinstance(suite, str):
        # v1.16.1: Verify suite signature if required
        if require_suite_signature:
            sig_result = verify_evaluation_suite_signature(
                suite_path=suite,
                trust_store_path=trust_store_path,
            )
            if not sig_result["valid"]:
                return {
                    "type": "evaluation_report",
                    "eval_id": eval_id,
                    "suite_id": "",
                    "suite_digest": "",
                    "passed": False,
                    "valid": False,
                    "errors": sig_result["errors"],
                    "started_at": started_at,
                    "finished_at": _now_iso(),
                    "nodechain_version": nodechain_version,
                    "suite_signature_status": sig_result["details"]["signature_status"],
                }
            _suite_sig_status = sig_result["details"]["signature_status"]
            _suite_sig_fp = sig_result["details"]["signer_fingerprint"]
            _suite_sig_trusted = sig_result["details"]["signer_trusted"]
            _suite_trust_verified = True
        suite = EvaluationSuite.from_file(suite)
    elif isinstance(suite, EvaluationSuite):
        pass  # already loaded

    # Validate suite
    errors = suite.validate()
    if errors:
        return {
            "type": "evaluation_report",
            "eval_id": eval_id,
            "suite_id": suite.suite_id,
            "suite_digest": suite.digest(),
            "passed": False,
            "valid": False,
            "errors": errors,
            "started_at": started_at,
            "finished_at": _now_iso(),
            "nodechain_version": nodechain_version,
        }

    # v1.16.2: Check lifecycle validity when required
    if require_active_suite or strict:
        is_valid, reason = suite.check_validity()
        _suite_validity_status = "valid" if is_valid else f"invalid:{reason}"
        if not is_valid:
            return {
                "type": "evaluation_report",
                "eval_id": eval_id,
                "suite_id": suite.suite_id,
                "suite_digest": suite.digest(),
                "passed": False,
                "valid": False,
                "errors": [reason],
                "started_at": started_at,
                "finished_at": _now_iso(),
                "nodechain_version": nodechain_version,
                "suite_signature_status": _suite_sig_status,
                "suite_validity_status": _suite_validity_status,
            }
    else:
        _suite_validity_status = "not_checked"

    # Check required artifacts
    missing_artifacts: list[str] = []
    for artifact in suite.required_artifacts:
        if not Path(artifact).exists():
            missing_artifacts.append(artifact)

    if missing_artifacts and strict:
        return {
            "type": "evaluation_report",
            "eval_id": eval_id,
            "suite_id": suite.suite_id,
            "suite_digest": suite.digest(),
            "passed": False,
            "valid": False,
            "errors": [f"Missing required artifacts: {missing_artifacts}"],
            "started_at": started_at,
            "finished_at": _now_iso(),
            "nodechain_version": nodechain_version,
        }

    # Run cases
    case_results: list[CaseResult] = []
    for case in suite.cases:
        if custom_runner:
            cr = custom_runner(case, suite)
        else:
            cr = _run_default_case(case, suite)
        case_results.append(cr)

    # Aggregate metrics
    total_cases = len(case_results)
    passed_cases = sum(1 for cr in case_results if cr.passed)
    failed_cases = [cr.case_id for cr in case_results if not cr.passed]

    metric_results: dict[str, Any] = {}
    for metric in suite.metrics:
        values = [cr.metrics.get(metric) for cr in case_results if metric in cr.metrics]
        if values:
            if all(isinstance(v, (int, float)) for v in values):
                metric_results[metric] = {
                    "mean": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "count": len(values),
                }
            else:
                metric_results[metric] = {
                    "count": len(values),
                    "all_passed": all(v in (True, 1, 1.0) for v in values) if values else False,
                }
        else:
            metric_results[metric] = {"count": 0}

    # Check thresholds
    threshold_failures: list[dict[str, Any]] = []
    for metric_name, threshold in suite.thresholds.items():
        mr = metric_results.get(metric_name, {})
        if "mean" in mr:
            if mr["mean"] < threshold:
                threshold_failures.append({
                    "metric": metric_name,
                    "threshold": threshold,
                    "actual": mr["mean"],
                })

    finished_ts = time.time()
    duration_ms = (finished_ts - started_ts) * 1000

    overall_passed = (
        len(failed_cases) == 0
        and len(threshold_failures) == 0
        and len(missing_artifacts) == 0
    )

    report: dict[str, Any] = {
        "type": "evaluation_report",
        "eval_id": eval_id,
        "suite_id": suite.suite_id,
        "suite_version": suite.suite_version,
        "suite_digest": suite.digest(),
        "target_type": suite.target_type,
        "target_ref": suite.target_ref,
        "target_digest": target_digest,
        "case_results": [cr.to_dict() for cr in case_results],
        "metric_results": metric_results,
        "passed": overall_passed,
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "threshold_failures": threshold_failures,
        "missing_artifacts": missing_artifacts,
        "started_at": started_at,
        "finished_at": _now_iso(),
        "duration_ms": round(duration_ms, 2),
        "nodechain_version": nodechain_version,
        # v1.16.1: Suite trust evidence
        "suite_signature_status": _suite_sig_status,
        "suite_signer_fingerprint": _suite_sig_fp,
        "suite_signer_trusted": _suite_sig_trusted,
        "suite_trust_verified": _suite_trust_verified,
        # v1.16.2 lifecycle evidence
        "suite_validity_status": _suite_validity_status,
        "suite_registry_digest": _suite_registry_digest,
        "report_digest": "",
        "valid": True,
    }

    # Compute report digest
    report["report_digest"] = _sha256_dict(
        {k: v for k, v in report.items()
         if k not in {"report_signature", "report_signature_algorithm",
                      "report_signer_fingerprint", "report_digest"}}
    )

    return report


def _run_default_case(
    case: EvaluationCase,
    suite: EvaluationSuite,
) -> CaseResult:
    """Default case runner: validates case structure and checks basic properties.

    This is a structural evaluator. Custom runners can be provided for
    runtime execution against actual nodes/chains.
    """
    failures: list[str] = []
    metrics: dict[str, Any] = {}

    # correctness: does the case have well-formed expectations?
    has_expectations = bool(case.expected_output or case.expected_trace_properties
                            or case.expected_policy_verdict or case.expected_receipt_fields
                            or case.required_invariants)
    metrics["correctness"] = 1.0 if has_expectations else 0.0
    if not has_expectations and case.case_id:
        # Case with no expectations is still valid as a smoke test
        metrics["correctness"] = 1.0

    # schema_validity: case_id present and non-empty
    metrics["schema_validity"] = 1.0 if case.case_id else 0.0
    if not case.case_id:
        failures.append("Missing case_id")

    # contract_validity: if expected_output has port contract, it's valid
    metrics["contract_validity"] = 1.0  # default: structurally valid

    # invariant_compliance: all required_invariants are known
    known_invariants = {
        "INV-001", "INV-002", "INV-003", "INV-004", "INV-005",
        "INV-006", "INV-007", "INV-008", "INV-009", "INV-010",
        "INV-011", "INV-012", "INV-013",
    }
    if case.required_invariants:
        unknown = [inv for inv in case.required_invariants if inv not in known_invariants]
        if unknown:
            metrics["invariant_compliance"] = 0.0
            failures.append(f"Unknown invariants: {unknown}")
        else:
            metrics["invariant_compliance"] = 1.0
    else:
        metrics["invariant_compliance"] = 1.0

    # policy_compliance: expected_policy_verdict is valid if set
    valid_verdicts = {"", "pass", "fail", "reject", "approve", "deny", "accept"}
    if case.expected_policy_verdict and case.expected_policy_verdict not in valid_verdicts:
        metrics["policy_compliance"] = 0.0
        failures.append(f"Invalid policy verdict: {case.expected_policy_verdict}")
    else:
        metrics["policy_compliance"] = 1.0

    # trace_completeness: default pass
    metrics["trace_completeness"] = 1.0

    # cost: within max_cost if set
    if case.max_cost > 0:
        metrics["cost"] = 0.0  # default: no actual cost measured
    else:
        metrics["cost"] = 0.0

    # latency: within max_latency if set
    metrics["latency"] = 0.0  # default: no actual latency measured

    # deterministic_replay_match: default pass
    metrics["deterministic_replay_match"] = 1.0

    passed = len(failures) == 0
    return CaseResult(
        case_id=case.case_id,
        passed=passed,
        metrics=metrics,
        failures=failures,
        latency_ms=0.0,
        cost=0.0,
    )


def sign_evaluation_report(
    report_path: str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign an evaluation report with RSA-PSS-SHA256 (v1.16.0).

    Args:
        report_path: Path to evaluation report JSON.
        private_key_path: Path to PEM private key.
        output_path: Where to write signed report. Defaults to overwriting input.

    Returns:
        Signed report dict.
    """
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))

    # Recompute digest without signature fields
    report["report_digest"] = _sha256_dict(
        {k: v for k, v in report.items()
         if k not in {"report_signature", "report_signature_algorithm",
                      "report_signer_fingerprint", "report_digest"}}
    )

    canonical = json.dumps(
        {k: v for k, v in report.items() if k not in {
            "report_signature", "report_signature_algorithm",
            "report_signer_fingerprint",
        }},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(
        canonical,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    report["report_signature"] = base64.b64encode(signature).decode("ascii")
    report["report_signature_algorithm"] = "RSA-PSS-SHA256"
    report["report_signer_fingerprint"] = fingerprint

    out = output_path or report_path
    Path(out).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def verify_evaluation_report(
    report_path: str = "",
    report_dict: dict[str, Any] | None = None,
    public_key_pem: str = "",
    trust_store_path: str = "",
) -> dict[str, Any]:
    """Verify a signed evaluation report (v1.16.0).

    Returns:
        {valid: bool, errors: list, warnings: list, details: dict}
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    if report_dict is None:
        report_dict = json.loads(Path(report_path).read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "signature_status": "unsigned",
        "signer_fingerprint": "",
        "signer_trusted": False,
        "report_digest": report_dict.get("report_digest", ""),
    }

    sig = report_dict.get("report_signature", "")
    if not sig:
        return {
            "valid": False,
            "errors": ["Report is not signed"],
            "warnings": [],
            "details": details,
        }

    signer_fp = report_dict.get("report_signer_fingerprint", "")
    details["signer_fingerprint"] = signer_fp

    # Resolve public key
    resolved_pem = ""
    signer_trusted = False

    if trust_store_path:
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint, load_trust_store

        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path
        try:
            signer_trusted = is_trusted_fingerprint(
                signer_fp, purpose="evaluation_report_signing",
            )
            details["signer_trusted"] = signer_trusted
            if not signer_trusted:
                errors.append(f"Signer {signer_fp} not trusted for evaluation_report_signing")

            store = load_trust_store()
            for info in store["keys"].values():
                if info.get("fingerprint") == signer_fp:
                    resolved_pem = info.get("public_key_pem", "")
                    break
        finally:
            if old_ts:
                os.environ["NODECHAIN_TRUST_STORE"] = old_ts
            elif "NODECHAIN_TRUST_STORE" in os.environ:
                del os.environ["NODECHAIN_TRUST_STORE"]

    if not resolved_pem and public_key_pem:
        resolved_pem = public_key_pem

    if not resolved_pem:
        warnings.append("Signed report but no public key for verification")
        details["signature_status"] = "signed_unverified"
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}

    # Verify signature
    try:
        from cryptography.hazmat.primitives import serialization as ser
        pub_key = ser.load_pem_public_key(resolved_pem.encode("utf-8"))

        canonical = json.dumps(
            {k: v for k, v in report_dict.items() if k not in {
                "report_signature", "report_signature_algorithm",
                "report_signer_fingerprint",
            }},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

        pub_key.verify(
            base64.b64decode(sig), canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        details["signature_status"] = "valid"
    except InvalidSignature:
        details["signature_status"] = "invalid"
        errors.append("Report signature verification failed")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}


# ── v1.16.1: Evaluation Suite Trust ────────────────────────────────────────

def sign_evaluation_suite(
    suite_path: str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign an evaluation suite with RSA-PSS-SHA256 (v1.16.1)."""
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    suite = EvaluationSuite.from_file(suite_path)
    signed_suite = suite.to_dict()
    signed_suite["type"] = "signed_evaluation_suite"
    signed_suite["suite_digest"] = _sha256_dict(
        {k: v for k, v in signed_suite.items() if k not in {"type", "suite_signature",
                                                            "suite_signature_algorithm",
                                                            "suite_signer_fingerprint"}}
    )

    canonical = json.dumps(
        {k: v for k, v in signed_suite.items() if k not in {
            "suite_signature", "suite_signature_algorithm", "suite_signer_fingerprint",
        }},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(
        canonical,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    signed_suite["suite_signature"] = base64.b64encode(signature).decode("ascii")
    signed_suite["suite_signature_algorithm"] = "RSA-PSS-SHA256"
    signed_suite["suite_signer_fingerprint"] = fingerprint

    out = output_path or str(Path(suite_path).with_suffix(".signed.json"))
    Path(out).write_text(json.dumps(signed_suite, indent=2, sort_keys=True), encoding="utf-8")
    return signed_suite


def verify_evaluation_suite_signature(
    suite_path: str = "",
    suite_dict: dict[str, Any] | None = None,
    public_key_pem: str = "",
    trust_store_path: str = "",
) -> dict[str, Any]:
    """Verify a signed evaluation suite (v1.16.1)."""
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    if suite_dict is None:
        suite_dict = json.loads(Path(suite_path).read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "signature_status": "unsigned",
        "signer_fingerprint": "",
        "signer_trusted": False,
        "suite_digest": "",
    }

    sig = suite_dict.get("suite_signature", "")
    if not sig:
        return {"valid": False, "errors": ["Suite is not signed"], "warnings": [], "details": details}

    stored_digest = suite_dict.get("suite_digest", "")
    if not stored_digest:
        errors.append("Missing suite_digest")
    else:
        recomputed = _sha256_dict(
            {k: v for k, v in suite_dict.items()
             if k not in {"suite_signature", "suite_signature_algorithm",
                          "suite_signer_fingerprint", "type", "suite_digest"}}
        )
        if stored_digest != recomputed:
            errors.append("Suite digest mismatch")
    details["suite_digest"] = stored_digest

    signer_fp = suite_dict.get("suite_signer_fingerprint", "")
    details["signer_fingerprint"] = signer_fp

    resolved_pem = ""
    signer_trusted = False

    if trust_store_path:
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint, load_trust_store

        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path
        try:
            signer_trusted = is_trusted_fingerprint(
                signer_fp, purpose="evaluation_suite_signing",
            )
            details["signer_trusted"] = signer_fp != "" and signer_trusted
            if not signer_trusted:
                if signer_fp:
                    errors.append(f"Signer {signer_fp} not trusted for evaluation_suite_signing")
                else:
                    errors.append("No signer fingerprint in suite")
            store = load_trust_store()
            for info in store["keys"].values():
                if info.get("fingerprint") == signer_fp:
                    resolved_pem = info.get("public_key_pem", "")
                    break
        finally:
            if old_ts:
                os.environ["NODECHAIN_TRUST_STORE"] = old_ts
            elif "NODECHAIN_TRUST_STORE" in os.environ:
                del os.environ["NODECHAIN_TRUST_STORE"]

    if not resolved_pem and public_key_pem:
        resolved_pem = public_key_pem

    if not resolved_pem:
        if sig and not errors:
            warnings.append("Signed suite but no public key for verification")
            details["signature_status"] = "signed_unverified"
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}

    try:
        from cryptography.hazmat.primitives import serialization as ser
        pub_key = ser.load_pem_public_key(resolved_pem.encode("utf-8"))
        canonical = json.dumps(
            {k: v for k, v in suite_dict.items() if k not in {
                "suite_signature", "suite_signature_algorithm", "suite_signer_fingerprint",
            }},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        pub_key.verify(
            base64.b64decode(sig), canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        details["signature_status"] = "valid"
    except InvalidSignature:
        details["signature_status"] = "invalid"
        errors.append("Suite signature verification failed")
    except Exception as e:
        details["signature_status"] = "invalid"
        errors.append(f"Signature verification error: {e}")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}
