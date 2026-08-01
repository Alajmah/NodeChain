"""Sandbox audit bundle generator (v1.6.0) with schema versioning (v1.6.1).

Produces a portable evidence artifact for a chain run, containing:
- Run report JSON
- Trust summary JSON
- Trace file
- Lockfile verification result
- Sandbox capability report
- Preset requirements
- Invariant results
- Platform info
- Human-readable SUMMARY.md

Every JSON file carries a schema_version stamp. The bundle can be verified
with `verify_audit_bundle()` or `nodechain audit-bundle --verify <zip>`.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

#: Schema version for the audit bundle format as a whole.
AUDIT_BUNDLE_SCHEMA_VERSION = "1"

#: Required files in every valid bundle.
REQUIRED_BUNDLE_FILES = frozenset({
    "SUMMARY.md",
    "bundle_meta.json",
    "invariants.json",
    "lockfile.json",
    "sandbox_capabilities.json",
    "namespace_detection.json",
    "preset.json",
    "enforcement_layers.json",
    "platform.json",
})

#: Schema version per file type.
_FILE_SCHEMA_VERSIONS: dict[str, str] = {
    "bundle_meta": "1",
    "invariants": "1",
    "lockfile": "1",
    "sandbox_capabilities": "1",
    "namespace_detection": "1",
    "preset": "1",
    "enforcement_layers": "1",
    "platform": "1",
    "report": "1",
    "trust_summary": "1",
    "trace": "1",
}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _stamp(data: dict[str, Any], file_type: str) -> dict[str, Any]:
    """Stamp a data dict with schema_version and type metadata.

    Works on a copy so the original is not mutated.
    """
    stamped = dict(data)
    stamped["schema_version"] = _FILE_SCHEMA_VERSIONS.get(file_type, "1")
    stamped["type"] = file_type
    return stamped


def _sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def _compute_bundle_sha256(zip_path: Path) -> str:
    """Compute SHA-256 of the entire ZIP file."""
    return hashlib.sha256(zip_path.read_bytes()).hexdigest()


def _build_file_manifest(files: dict[str, bytes]) -> list[dict[str, str]]:
    """Build a content manifest with SHA-256 for every file.

    Args:
        files: mapping of filename to raw bytes.

    Returns:
        List of {path, sha256, size} entries sorted by path.
    """
    manifest = []
    for path in sorted(files):
        raw = files[path]
        manifest.append({
            "path": path,
            "sha256": _sha256_bytes(raw),
            "size": len(raw),
        })
    return manifest


def verify_audit_bundle(zip_path: str, pubkey_path: str = "", require_signature: bool = False) -> dict[str, Any]:
    """Verify a sandbox audit bundle ZIP.

    Checks:
    1. ZIP is openable.
    2. All required files present.
    3. Every JSON file has a schema_version field.
    4. bundle_meta.json has audit_bundle_schema_version.
    5. Content manifest SHA-256 hashes match (v1.6.2).
    6. No unexpected files present (v1.6.2).
    7. Signature verification if pubkey provided (v1.7.0).
    8. --require-signature: fail if not signed or not verified (v1.7.1).

    Returns a result dict.
    """
    result: dict[str, Any] = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "files_checked": 0,
        "missing_files": [],
        "schema_versions": {},
        "hash_mismatches": [],
        "unexpected_files": [],
        "signature_status": "not_checked",
        "signature_reason": "",
    }

    p = Path(zip_path)
    if not p.exists():
        result["valid"] = False
        result["errors"].append(f"Bundle file not found: {zip_path}")
        return result

    try:
        zf = zipfile.ZipFile(p, "r")
    except zipfile.BadZipFile:
        result["valid"] = False
        result["errors"].append("Not a valid ZIP file")
        return result

    with zf:
        names = set(zf.namelist())

        # Check required files
        for req in REQUIRED_BUNDLE_FILES:
            if req not in names:
                result["missing_files"].append(req)
                result["errors"].append(f"Missing required file: {req}")

        # Parse bundle_meta first to get the manifest
        manifest: list[dict] | None = None
        manifest_paths: set[str] = set()

        # Check every JSON file has schema_version
        json_files = [n for n in names if n.endswith(".json")]
        for jf in json_files:
            result["files_checked"] += 1
            try:
                raw = zf.read(jf)
                data = json.loads(raw)
            except Exception as exc:
                result["errors"].append(f"Cannot parse {jf}: {exc}")
                continue

            if isinstance(data, dict):
                sv = data.get("schema_version", "")
                ft = data.get("type", "")
                if not sv:
                    result["warnings"].append(f"{jf} missing schema_version")
                else:
                    result["schema_versions"][jf] = sv

                # bundle_meta.json must have audit_bundle_schema_version
                if jf == "bundle_meta.json":
                    absv = data.get("audit_bundle_schema_version", "")
                    if not absv:
                        result["errors"].append(
                            "bundle_meta.json missing audit_bundle_schema_version"
                        )
                    else:
                        result["schema_versions"]["audit_bundle"] = absv

                    # Extract manifest (v1.6.2)
                    manifest = data.get("files", [])
                    if manifest:
                        for entry in manifest:
                            manifest_paths.add(entry.get("path", ""))

        # Check SUMMARY.md exists and has compliance status
        if "SUMMARY.md" in names:
            md = zf.read("SUMMARY.md").decode("utf-8", errors="replace")
            if "Compliance Status" not in md:
                result["warnings"].append(
                    "SUMMARY.md missing 'Compliance Status' section"
                )
        else:
            result["errors"].append("Missing SUMMARY.md")

        # ── v1.6.2: Content integrity checks ──

        if manifest:
            # Check 5a: SHA-256 hash verification
            for entry in manifest:
                fpath = entry.get("path", "")
                expected_hash = entry.get("sha256", "")
                expected_size = entry.get("size", -1)

                if fpath not in names:
                    result["errors"].append(
                        f"Manifest references missing file: {fpath}"
                    )
                    continue

                raw = zf.read(fpath)
                actual_hash = _sha256_bytes(raw)
                actual_size = len(raw)

                if actual_hash != expected_hash:
                    result["hash_mismatches"].append(fpath)
                    result["errors"].append(
                        f"Hash mismatch for {fpath}: "
                        f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
                    )

                if expected_size >= 0 and actual_size != expected_size:
                    result["errors"].append(
                        f"Size mismatch for {fpath}: "
                        f"expected {expected_size}, got {actual_size}"
                    )

            # Check 5b: No unexpected files (bundle_meta.json excluded —
            # it IS the manifest container and cannot hash itself)
            for actual_path in names:
                if actual_path == "bundle_meta.json":
                    continue
                if actual_path not in manifest_paths:
                    result["unexpected_files"].append(actual_path)
                    result["errors"].append(
                        f"Unexpected file not in manifest: {actual_path}"
                    )

            result["manifest_entries"] = len(manifest)
        else:
            result["warnings"].append(
                "No content manifest in bundle_meta.json (bundle predates v1.6.2)"
            )

        # ── v1.7.0: Signature verification ──

        # Re-read bundle_meta for signature check
        bundle_meta_raw = zf.read("bundle_meta.json")
        bundle_meta_data = json.loads(bundle_meta_raw)

        has_signature = bool(bundle_meta_data.get("signature", ""))

        if pubkey_path:
            # Operator explicitly requested signature verification
            if not has_signature:
                result["signature_status"] = "missing"
                result["signature_reason"] = "Bundle is not signed but --pubkey was provided"
                result["errors"].append(
                    "Signature required (--pubkey provided) but bundle is not signed"
                )
            else:
                try:
                    from nodechain.cli.bundle_signing import verify_bundle_signature
                    sig_result = verify_bundle_signature(bundle_meta_data, pubkey_path)
                    result["signature_status"] = "valid" if sig_result["valid"] else "invalid"
                    result["signature_reason"] = sig_result["reason"]
                    if not sig_result["valid"]:
                        result["errors"].append(
                            f"Signature verification failed: {sig_result['reason']}"
                        )
                except Exception as exc:
                    result["signature_status"] = "error"
                    result["signature_reason"] = str(exc)
                    result["errors"].append(f"Signature verification error: {exc}")
        elif has_signature:
            # Bundle has signature but no pubkey provided — informational
            result["signature_status"] = "signed_not_verified"
            result["signature_reason"] = "Bundle is signed but --pubkey not provided"
            result["warnings"].append(
                "Bundle is signed but no --pubkey provided for verification"
            )

        # ── v1.7.1: --require-signature enforcement ──
        if require_signature:
            sig_status = result["signature_status"]
            if sig_status in ("not_checked", "present_not_verified", "signed_not_verified"):
                # Signature not checked because no pubkey
                if not pubkey_path:
                    result["errors"].append(
                        "--require-signature requires --pubkey for signature verification"
                    )
            elif sig_status == "missing":
                result["errors"].append(
                    "--require-signature: bundle is not signed"
                )
            elif sig_status == "invalid":
                result["errors"].append(
                    "--require-signature: signature verification failed"
                )
            # If status is "valid", no error — passes

    if result["errors"]:
        result["valid"] = False

    return result


def _get_git_info() -> dict[str, str]:
    """Get git commit/tag info if available."""
    info = {"git_commit": "", "git_tag": "", "git_branch": ""}
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            info["git_commit"] = result.stdout.strip()
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            info["git_tag"] = result.stdout.strip()
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            info["git_branch"] = result.stdout.strip()
    except Exception:
        pass
    return info


def _get_platform_info() -> dict[str, str]:
    """Get platform/kernel/container detection."""
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "python_version": sys.version,
        "machine": platform.machine(),
        "processor": platform.processor(),
    }

    # Container detection
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
        if "docker" in cgroup or "lxc" in cgroup or "containerd" in cgroup:
            info["container_detected"] = "yes"
            if "lxc" in cgroup:
                info["container_type"] = "lxc"
            elif "docker" in cgroup:
                info["container_type"] = "docker"
        else:
            info["container_detected"] = "no"
    except Exception:
        info["container_detected"] = "unknown"

    # Proxmox detection
    try:
        if Path("/proc/1/cgroup").read_text():
            info["cgroup_available"] = "yes"
    except Exception:
        info["cgroup_available"] = "unknown"

    return info


def _get_sandbox_capabilities() -> dict[str, Any]:
    """Get sandbox capability report."""
    try:
        from nodechain.sdk.os_sandbox import detect_sandbox_capabilities
        caps = detect_sandbox_capabilities()
        return caps.to_dict()
    except Exception as e:
        return {"error": str(e)}


def _get_namespace_capabilities() -> dict[str, Any]:
    """Get namespace detection."""
    try:
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        return {
            "namespace_available": caps.namespace_available,
            "namespace_mode": caps.namespace_mode,
            "already_nested": caps.already_nested,
            "mount_namespace_available": caps.mount_namespace_available,
            "pid_namespace_available": caps.pid_namespace_available,
            "network_namespace_available": caps.network_namespace_available,
            "user_namespace_available": caps.user_namespace_available,
            "backend_name": caps.backend_name,
        }
    except Exception as e:
        return {"error": str(e)}


def _get_preset_info() -> dict[str, Any]:
    """Get current preset info."""
    preset_name = os.environ.get("NODECHAIN_POLICY_PRESET", "")
    if not preset_name:
        return {"preset": "", "source": ""}
    source = os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE", "")
    try:
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset(preset_name)
        if preset:
            return {
                "preset": preset_name,
                "source": source,
                "config": preset.to_dict(),
            }
    except Exception:
        pass
    return {"preset": preset_name, "source": source}


def _get_lockfile_status() -> dict[str, Any]:
    """Get lockfile verification status."""
    try:
        from nodechain.sdk.lockfile import verify_lockfile, LOCKFILE_NAME
        result = verify_lockfile()
        return {
            "lockfile_path": LOCKFILE_NAME,
            "valid": result.get("valid", False),
            "locked_count": result.get("locked_count", 0),
            "current_count": result.get("current_count", 0),
            "mismatches": result.get("mismatches", []),
            "missing": result.get("missing", []),
            "error": result.get("error", ""),
        }
    except Exception as e:
        return {"error": str(e), "valid": False}


def _build_trust_summary_for_audit(
    run_id: str, db_path: str, trace_dir: str
) -> tuple[dict[str, Any] | None, list]:
    """Build trust summary and validate invariants.

    Returns (summary_dict, violations).
    """
    try:
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        from nodechain.runtime.persistence import StateManager

        sm = StateManager(db_path=db_path)
        state = sm.load(run_id)
        if state is None:
            return None, []

        summary = TrustSummary(run_id=run_id)
        summary.lockfile_verified = True  # Will be updated from lockfile check
        summary.policy_preset = os.environ.get("NODECHAIN_POLICY_PRESET", "")
        summary.preset_source = os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE", "")

        origins = getattr(state, "node_origins", {}) or {}
        for node_id, origin in origins.items():
            record = NodeTrustRecord(
                node_id=node_id,
                trust_level=origin.get("trust_level", "built_in"),
                isolation_mode=origin.get("isolation_mode", "in_process"),
                child_policy_enforced=origin.get("child_policy_enforced", False),
                env_filtered=origin.get("env_filtered", False),
                temp_dir_isolated=origin.get("temp_dir_isolated", False),
                origin=origin.get("origin", "built_in"),
            )
            summary.add_node(record)

        violations = summary.validate_invariants(strict=True)
        return summary.to_dict(), violations
    except Exception as e:
        return {"error": str(e)}, []


def _classify_enforcement_layers(
    summary: dict | None,
    preset_info: dict,
    sandbox_caps: dict,
    namespace_caps: dict,
) -> dict[str, list[dict[str, str]]]:
    """Classify enforcement layers into required/enforced/advisory/unavailable/skipped."""
    result = {
        "required": [],
        "enforced": [],
        "advisory": [],
        "unavailable": [],
        "skipped": [],
    }

    preset_config = preset_info.get("config", {})

    # Subprocess isolation (always required for untrusted)
    result["required"].append({
        "layer": "subprocess_isolation",
        "invariant": "INV-001",
        "status": "always required for untrusted nodes",
    })

    # Child policy enforcement
    result["required"].append({
        "layer": "child_policy_enforcement",
        "invariant": "INV-002",
        "status": "import + filesystem + subprocess + network hooks",
    })

    # Seccomp
    if preset_config.get("seccomp_required"):
        if sandbox_caps.get("seccomp_available"):
            result["enforced"].append({
                "layer": "seccomp_syscall_filtering",
                "profile": sandbox_caps.get("seccomp_profile_name", "default"),
                "blocked_syscalls": 20,
            })
        else:
            result["unavailable"].append({
                "layer": "seccomp_syscall_filtering",
                "reason": "not available on this platform",
            })

    # Cgroup
    if preset_config.get("cgroup_limits_requested"):
        if sandbox_caps.get("cgroup_available"):
            result["enforced"].append({
                "layer": "cgroup_v2_limits",
                "memory_mb": preset_config.get("cgroup_memory_max_mb", 0),
                "pids_max": preset_config.get("cgroup_pids_max", 0),
                "cpu_quota": preset_config.get("cgroup_cpu_max_quota", 0),
            })
        else:
            result["unavailable"].append({
                "layer": "cgroup_v2_limits",
                "reason": "cgroup not available",
            })

    # Network namespace
    if preset_config.get("network_namespace_required"):
        if namespace_caps.get("network_namespace_available"):
            result["enforced"].append({
                "layer": "network_namespace",
                "isolation": "no network interfaces",
            })
        else:
            result["unavailable"].append({
                "layer": "network_namespace",
                "reason": "namespace creation not available",
            })

    # Mount confinement
    if preset_config.get("mount_confinement_required"):
        result["required"].append({
            "layer": "mount_confinement",
            "invariant": "INV-012",
            "status": "chroot: /package + /tmp only",
        })
        if platform.system() != "Linux":
            result["unavailable"].append({
                "layer": "mount_confinement",
                "reason": "Linux only",
            })

    # PID namespace
    if preset_config.get("pid_namespace_required"):
        if namespace_caps.get("pid_namespace_available"):
            result["enforced"].append({
                "layer": "pid_namespace",
                "child_pid": 1,
            })
        else:
            result["unavailable"].append({
                "layer": "pid_namespace",
                "reason": "namespace creation not available",
            })

    # Advisory layers
    result["advisory"].append({
        "layer": "rlimit" if platform.system() == "Linux" else "job_objects",
        "platform": platform.system(),
    })

    # Procfs (optional)
    result["skipped"].append({
        "layer": "procfs_remount",
        "reason": "optional (enable_procfs_isolation)",
    })

    return result


def _build_summary_md(
    run_id: str,
    version: str,
    platform_info: dict,
    preset_info: dict,
    layers: dict[str, list],
    violations: list,
    lockfile: dict,
    sandbox_caps: dict,
    namespace_caps: dict,
) -> str:
    """Build human-readable SUMMARY.md."""
    has_violations = len(violations) > 0
    error_count = sum(1 for v in violations if v.severity == "error")
    if has_violations and error_count > 0:
        compliance = "❌ NON-COMPLIANT"
    elif has_violations:
        compliance = "⚠️ COMPLIANT WITH WARNINGS"
    else:
        compliance = "✅ COMPLIANT"

    preset_name = preset_info.get("preset", "none")

    lines = [
        f"# Sandbox Audit Bundle — Run {run_id}",
        "",
        f"**Generated**: {_utc_now()}",
        f"**NodeChain version**: {version}",
        f"**Bundle schema version**: {AUDIT_BUNDLE_SCHEMA_VERSION}",
        "",
        "## Compliance Status",
        "",
        f"**{compliance}**",
        "",
        f"- Active preset: **{preset_name}**",
        f"- Required layers: {len(layers.get('required', [])) + len(layers.get('enforced', []))}",
        f"- Enforced layers: {len(layers.get('enforced', []))}",
        f"- Unavailable layers: {len(layers.get('unavailable', []))}",
        f"- Failed invariants: {error_count}",
        f"- Total violations: {len(violations)}",
        "",
        "## Platform Summary",
        "",
        f"- OS: {platform_info.get('platform', 'unknown')}",
        f"- Kernel: {platform_info.get('platform_release', 'unknown')}",
        f"- Python: {platform_info.get('python_version', 'unknown')}",
        f"- Container: {platform_info.get('container_detected', 'unknown')}",
        "",
        "## Policy Preset",
        "",
    ]
    lines.append(f"- Preset: **{preset_name}**")
    lines.append(f"- Source: {preset_info.get('source', '')}")
    lines.append("")

    # Enforcement layers
    lines.append("## Enforcement Layers")
    lines.append("")
    lines.append("### Required & Enforced")
    for item in layers.get("enforced", []):
        lines.append(f"- ✅ {item.get('layer', '')}: {_json_compact(item)}")
    lines.append("")

    lines.append("### Required")
    for item in layers.get("required", []):
        lines.append(f"- 🔵 {item.get('layer', '')}: {item.get('status', '')} ({item.get('invariant', '')})")
    lines.append("")

    if layers.get("unavailable"):
        lines.append("### Unavailable")
        for item in layers["unavailable"]:
            lines.append(f"- ❌ {item.get('layer', '')}: {item.get('reason', '')}")
        lines.append("")

    if layers.get("advisory"):
        lines.append("### Advisory")
        for item in layers["advisory"]:
            lines.append(f"- ⚪ {item.get('layer', '')} ({item.get('platform', '')})")
        lines.append("")

    if layers.get("skipped"):
        lines.append("### Skipped (Optional)")
        for item in layers["skipped"]:
            lines.append(f"- ⏭️ {item.get('layer', '')}: {item.get('reason', '')}")
        lines.append("")

    # Trust violations
    lines.append("## Trust Invariants")
    lines.append("")
    if violations:
        lines.append(f"**{len(violations)} violations found:**")
        lines.append("")
        for v in violations:
            lines.append(f"- [{v.code}] {v.severity.upper()} {v.node_id}: {v.invariant}")
            lines.append(f"  - expected: {v.expected}")
            lines.append(f"  - actual: {v.actual}")
    else:
        lines.append("✅ **All trust invariants satisfied.**")
    lines.append("")

    # Lockfile
    lines.append("## Lockfile")
    lines.append("")
    if lockfile.get("valid"):
        lines.append(f"✅ Verified ({lockfile.get('locked_count', 0)} packages)")
    elif lockfile.get("error"):
        lines.append(f"❌ Error: {lockfile['error']}")
    else:
        lines.append("⚠️ Not verified or drifted")
    lines.append("")

    # Sandbox capabilities
    lines.append("## Sandbox Capabilities")
    lines.append("")
    for key, val in sandbox_caps.items():
        if val and key != "error":
            lines.append(f"- {key}: {val}")
    lines.append("")

    # Namespace capabilities
    lines.append("## Namespace Detection")
    lines.append("")
    for key, val in namespace_caps.items():
        if key != "error":
            lines.append(f"- {key}: {val}")
    lines.append("")

    return "\n".join(lines)


def _json_compact(d: dict) -> str:
    """Compact JSON for inline display."""
    return json.dumps(d, separators=(",", ":"))


def generate_audit_bundle(
    run_id: str,
    db_path: str = "data/chain_state.db",
    trace_dir: str = "data/traces",
    output_path: str = "",
    strict: bool = False,
    sign_key: str = "",
) -> int:
    """Generate a sandbox audit bundle.

    Returns exit code: 0 = ok, 2 = not found, 15 = trust violation (strict).
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_NOT_FOUND, EXIT_TRUST_VIOLATION
    import nodechain

    version = nodechain.__version__

    # Gather all evidence
    platform_info = _get_platform_info()
    git_info = _get_git_info()
    sandbox_caps = _get_sandbox_capabilities()
    namespace_caps = _get_namespace_capabilities()
    preset_info = _get_preset_info()
    lockfile = _get_lockfile_status()

    # Load run state
    from nodechain.runtime.persistence import StateManager
    sm = StateManager(db_path=db_path)
    state = sm.load(run_id)
    if state is None:
        print(f"Run not found: {run_id}")
        return EXIT_NOT_FOUND

    # Build trust summary
    summary_dict, violations = _build_trust_summary_for_audit(run_id, db_path, trace_dir)

    # Classify layers
    layers = _classify_enforcement_layers(summary_dict, preset_info, sandbox_caps, namespace_caps)

    # Build SUMMARY.md
    summary_md = _build_summary_md(
        run_id, version, platform_info, preset_info, layers,
        violations, lockfile, sandbox_caps, namespace_caps,
    )

    # Load report
    try:
        from nodechain.cli.report import report_run
        report_data = report_run(run_id, db_path, trace_dir, output=None)
    except Exception as e:
        report_data = {"error": str(e)}

    # Find trace file
    trace_path = Path(trace_dir) / f"{run_id}.json"
    trace_data = {}
    if trace_path.exists():
        try:
            trace_data = json.loads(trace_path.read_text())
        except Exception:
            pass

    # Determine output path
    if not output_path:
        output_path = f"audit_bundle_{run_id}.zip"
    output = Path(output_path)

    # ── Build all file contents in memory first ──
    files: dict[str, bytes] = {}

    files["SUMMARY.md"] = summary_md.encode("utf-8")
    files["report.json"] = json.dumps(_stamp(report_data, "report"), indent=2, default=str).encode("utf-8")
    if summary_dict:
        files["trust_summary.json"] = json.dumps(_stamp(summary_dict, "trust_summary"), indent=2, default=str).encode("utf-8")
    files["invariants.json"] = json.dumps(_stamp({
        "violations": [
            {
                "code": v.code,
                "severity": v.severity,
                "node_id": v.node_id,
                "invariant": v.invariant,
                "expected": v.expected,
                "actual": v.actual,
            }
            for v in violations
        ],
        "total": len(violations),
        "errors": sum(1 for v in violations if v.severity == "error"),
    }, "invariants"), indent=2).encode("utf-8")
    files["lockfile.json"] = json.dumps(_stamp(lockfile, "lockfile"), indent=2, default=str).encode("utf-8")
    files["sandbox_capabilities.json"] = json.dumps(_stamp(sandbox_caps, "sandbox_capabilities"), indent=2, default=str).encode("utf-8")
    files["namespace_detection.json"] = json.dumps(_stamp(namespace_caps, "namespace_detection"), indent=2, default=str).encode("utf-8")
    files["preset.json"] = json.dumps(_stamp(preset_info, "preset"), indent=2, default=str).encode("utf-8")
    files["enforcement_layers.json"] = json.dumps(_stamp(layers, "enforcement_layers"), indent=2, default=str).encode("utf-8")
    if trace_data:
        files["trace.json"] = json.dumps(_stamp(trace_data, "trace"), indent=2, default=str).encode("utf-8")
    files["platform.json"] = json.dumps(_stamp(platform_info, "platform"), indent=2, default=str).encode("utf-8")

    # ── Compute content manifest (v1.6.2) ──
    manifest = _build_file_manifest(files)

    # ── Build bundle_meta with manifest ──
    bundle_meta = {
        "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "nodechain_version": version,
        "git_tag": git_info.get("git_tag", ""),
        "git_commit": git_info.get("git_commit", ""),
        "run_id": run_id,
        "files": manifest,
    }

    # ── Sign bundle if signing key provided (v1.7.0) ──
    signature_status = "unsigned"
    signer_fingerprint = ""
    if sign_key:
        try:
            from nodechain.cli.bundle_signing import sign_bundle_meta
            bundle_meta = sign_bundle_meta(bundle_meta, sign_key)
            signature_status = "signed"
            signer_fingerprint = bundle_meta.get("signer_key_fingerprint", "")
            print(f"  Signature: RSA-PSS-SHA256")
            print(f"  Signer fingerprint: {signer_fingerprint}")
        except Exception as e:
            print(f"  WARNING: Signing failed: {e}")
            signature_status = "signing_failed"

    files["bundle_meta.json"] = json.dumps(_stamp(bundle_meta, "bundle_meta"), indent=2, default=str).encode("utf-8")

    # ── Write ZIP ──
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, fdata in files.items():
            zf.writestr(fname, fdata)

    # ── Compute top-level bundle SHA-256 (v1.6.2) ──
    bundle_sha256 = _compute_bundle_sha256(output)

    # ── Update SUMMARY.md with integrity + signature info (v1.6.2/v1.7.0) ──
    summary_footer = f"\n---\n\n## Bundle Integrity\n\n"
    summary_footer += f"- Bundle SHA-256: `{bundle_sha256}`\n"
    summary_footer += f"- Manifest entries: {len(manifest)}\n"
    summary_footer += f"- Signature: **{signature_status}**\n"
    if signer_fingerprint:
        summary_footer += f"- Signer fingerprint: `{signer_fingerprint}`\n"

    # Rewrite ZIP with updated SUMMARY
    with zipfile.ZipFile(output, "a") as zf:
        pass  # Can't update in-place; rewrite

    # Actually rewrite the whole ZIP with updated SUMMARY
    updated_files: dict[str, bytes] = {}
    with zipfile.ZipFile(output, "r") as zf_read:
        for name in zf_read.namelist():
            if name == "SUMMARY.md":
                updated_files[name] = (summary_md + summary_footer).encode("utf-8")
            else:
                updated_files[name] = zf_read.read(name)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf_write:
        for fname, fdata in updated_files.items():
            zf_write.writestr(fname, fdata)

    # Recompute bundle SHA-256 after SUMMARY update
    bundle_sha256 = _compute_bundle_sha256(output)

    print(f"Audit bundle written to: {output}")
    print(f"  Size: {len(output.read_bytes())} bytes")
    print(f"  Bundle SHA-256: {bundle_sha256}")
    print(f"  Manifest entries: {len(manifest)}")
    print(f"  Signature: {signature_status}")
    print(f"  Violations: {len(violations)}")
    if violations:
        for v in violations:
            print(f"  [{v.code}] {v.severity.upper()} {v.node_id}: {v.invariant}")

    # Strict mode: exit 15 if trust violations
    if strict and violations:
        error_count = sum(1 for v in violations if v.severity == "error")
        if error_count > 0:
            return EXIT_TRUST_VIOLATION

    return EXIT_OK
