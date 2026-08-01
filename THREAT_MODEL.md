# NodeChain Threat Model

## Overview

NodeChain is a **local trust platform** for executing autonomous node chains
with governed, process-isolated untrusted execution. The threat model addresses
what NodeChain protects against and what it does not.

## Assets

| Asset | Protection |
|-------|------------|
| Host filesystem | Python hooks + chroot + mount namespace |
| Host network | Network namespace + socket hooks |
| Host processes | PID namespace + seccomp |
| Host memory | Cgroup v2 limits + Job Objects (Windows) |
| Runtime integrity | Trust invariants + reconciler + trace replay |
| Signed artifacts | RSA-PSS-SHA256 + trust store + digest verification |
| Deployment targets | Host key pinning + adapter manifest + secret policy |
| Registry entries | Certification chain + publisher trust + lifecycle |

## Threat Actors

### T1: Malicious Node Package
**Scenario**: A node package contains code intended to escape the sandbox or
exfiltrate data.

**Mitigations**:
- Python-level enforcement (import, filesystem, subprocess, network hooks)
- Process isolation (separate subprocess)
- OS sandbox (seccomp, cgroup, namespaces, chroot)
- Package policy enforcement (declared capabilities are enforced)
- Certified registry consumption gate

**Residual risk**: Kernel exploits, C extension escape, side-channel attacks.

### T2: Forged Artifact
**Scenario**: An attacker forges a signed artifact (audit bundle, attestation,
certification, etc.) to deceive verification.

**Mitigations**:
- RSA-PSS-SHA256 signatures with 3072-bit keys
- SHA-256 content digests verified on every check
- Trust store with purpose-scoped keys
- Canonical JSON signing (deterministic serialization)

**Residual risk**: Private key compromise, hash collision (negligible with SHA-256).

### T3: Untrusted Publisher
**Scenario**: An attacker publishes a package to the registry claiming to be
a trusted publisher.

**Mitigations**:
- `registry_publishing` trust store purpose
- Signed registry entries
- Publisher fingerprint verification
- Consumption policy (`trusted_publisher_only`)

**Residual risk**: Publisher key compromise, trust store tampering.

### T4: Stale/Revoked Certification
**Scenario**: A package's certification has expired or been revoked, but is
still used.

**Mitigations**:
- Certification validity windows (`valid_from`, `valid_until`)
- Certification status tracking (`certified`, `denied`, `revoked`)
- Registry entry lifecycle (`active`, `deprecated`, `revoked`)
- Consumption policy (`require_active_only`, `certified_only`)

**Residual risk**: No automatic time sync verification (no trusted timestamp).

### T5: Deployment Target Compromise
**Scenario**: An attacker modifies the deployment target after deployment.

**Mitigations**:
- Drift detection (6 comparison fields)
- Evidence strength classification (4 levels)
- Governed drift remediation
- Release history with rollback provenance

**Residual risk**: No continuous monitoring (drift is checked on-demand).

### T6: Evidence Chain Break
**Scenario**: An attacker removes or modifies evidence artifacts to hide
actions.

**Mitigations**:
- Signed evidence reports (index, timeline, replay)
- SHA-256 digest references throughout the chain
- Atomic writes for trust store and registry
- Audit logs for trust store, release history, and registry

**Residual risk**: No content-addressed storage (source files can be deleted).

## Trust Model Assumptions

1. **Local trust store is authoritative** — whoever controls the trust store
   controls what is trusted.
2. **Private keys are secure** — key compromise breaks all signatures from
   that key.
3. **Host OS is not compromised** — NodeChain cannot protect against a
   compromised host kernel.
4. **Platform APIs are honest** — seccomp, cgroup, and namespace APIs behave
   as documented.
5. **Python runtime is not subverted** — bytecode injection or C extension
   abuse can bypass Python-level hooks.

## Signing Assumptions

- RSA-PSS with SHA-256 is assumed to be existentially unforgeable
- 3072-bit keys provide ~128-bit security level
- Canonical JSON serialization is deterministic (sort_keys=True, compact separators)
- Signatures cover content digests, not full content (performance)

## Sandbox Assumptions

- Seccomp filters are evaluated in kernel space and cannot be bypassed by
  unprivileged processes
- Cgroup limits are enforced by the kernel
- Namespace isolation prevents cross-namespace visibility
- Chroot requires root (CAP_SYS_CHROOT)
- Python hooks can be bypassed by C extensions or direct syscalls

## Registry Trust Assumptions

- Registry entries are only as trustworthy as their publisher
- Certification is only as trustworthy as the certifier
- Evaluation is only as meaningful as the suite
- The chain: package → certification → evaluation → suite → publisher/certifier keys
  is as strong as its weakest link

## Deployment Adapter Risks

- SSH adapter has direct shell access to target host
- API adapter has API-level access (start, stop, reboot, upload, apply)
- Adapter manifests control execution but are only as trustworthy as their signer
- Secret reference policy prevents inline secrets but does not prevent
  environment variable leaks

## Non-Goals

NodeChain does NOT attempt to protect against:
- Kernel-level exploits from sandboxed processes
- Physical access attacks
- Supply chain attacks on Python packages (pip dependencies)
- Network-level attacks (MITM, DNS poisoning)
- Cryptographic advances breaking RSA or SHA-256
- Social engineering
- Insider threats with host access

## Future Hardening

- Trusted timestamp authority integration
- Content-addressed artifact storage
- Key rotation and lifecycle management
- Remote registry support
- Transparency log inclusion
- User namespace for unprivileged sandboxing
