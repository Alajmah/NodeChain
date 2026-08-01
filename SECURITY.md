# Security Policy

## Supported Versions

NodeChain is under active development. Security fixes are applied to the
latest `master` branch.

| Version | Supported |
|---------|-----------|
| 3.5.x   | ✅        |
| < 3.5   | ❌        |

## Secret Handling

NodeChain is designed to **never** serialize secret values.

- **Secret references** (not values) are stored in deployment manifests, receipts, and traces
- `forbid_inline_secrets=True` is the secure default for deployment adapters
- Trust store stores public keys only — private keys never enter the store
- `.env` files are gitignored and must never be committed
- Proxmox API tokens are passed via environment variables, not stored in artifacts

If you find a committed secret in this repository, treat it as compromised
and rotate it immediately.

## Trust Boundary

NodeChain operates on a **local trust model**:

- The **trust store** is the root of trust — it stores public keys with
  purpose constraints (11 purposes as of v1.18.1)
- All signing uses **RSA-PSS-SHA256** with 3072-bit keys (recommended)
- Verification checks: signature validity, digest integrity, signer trust,
  and purpose authorization
- Trust is **not global** — a signature trusted by one NodeChain installation
  is not automatically trusted by another

### What the trust store does NOT do

- It does not provide a public key infrastructure (PKI)
- It does not validate key provenance beyond the local store
- It does not enforce key rotation or expiry (manual process)
- It does not integrate with timestamp authorities (planned)

## Sandbox Limitations

NodeChain uses a layered sandbox model. Each layer is independently bypassable
by a sufficiently privileged attacker. Defense-in-depth is the strategy.

### Python-level enforcement (all platforms)
- Import hooks (`__import__` wrapper)
- Filesystem hooks (`builtins.open` wrapper)
- Subprocess hooks
- Network hooks (`socket` wrapper)

**Limitation**: These are bypassable by C extensions, `ctypes`, or direct
syscall access. They are the first layer, not the only layer.

### Process isolation (all platforms)
- Untrusted nodes run in a subprocess
- CWD is set to a temporary directory
- Environment is minimized

### OS-level sandbox (Linux only, privileged)
- **Seccomp**: 20 dangerous syscalls blocked (INV-007)
- **Cgroup v2**: Per-invocation memory/CPU/pid limits (INV-009)
- **Network namespace**: Isolated network stack (INV-011)
- **Mount namespace + chroot**: Filesystem confinement (INV-012)
- **PID namespace**: Process isolation (INV-013)
- **Procfs remount**: Namespace-local `/proc`

**Limitation**: OS sandboxing requires root or specific capabilities.
On Windows, only Job Objects are available (memory limits only).
On macOS, only detection is available (no enforcement).

### What the sandbox does NOT prevent
- Kernel exploits
- Side-channel attacks
- Attacks from the host process
- Time-based attacks

## Deployment Adapter Safety

Deployment adapters execute real operations on infrastructure:

- **SSH adapter**: Requires SSH key access to target host
- **API adapter**: Requires Proxmox API token with appropriate permissions
- **Host key pinning**: Required in strict mode
- **Secret reference policy**: Inline secrets forbidden by default

**Risk**: A compromised deployment adapter can modify or destroy infrastructure.
Limit adapter permissions using Proxmox token scopes.

## Responsible Disclosure

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Use **GitHub's private vulnerability reporting** (the "Report a vulnerability"
   button on the Security tab) — this is the preferred channel
3. Provide a description and proof of concept
4. Allow reasonable time for a fix before public disclosure

## Signing Key Security

- Generate keys with `openssl genrsa -out key.pem 3072`
- Store private keys outside the repository
- Use separate keys for different purposes
- Rotate keys periodically
- Never share private keys
