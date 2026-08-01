#!/usr/bin/env bash
#
# NodeChain Linux Setup Script — Proxmox Baseline
#
# Runs on a fresh Ubuntu/Debian VM to set up NodeChain for validation.
#
# Usage:
#   curl -sL <repo-url>/scripts/setup_linux.sh | bash
#   or:
#   bash scripts/setup_linux.sh
#
set -euo pipefail

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  NodeChain Linux Setup — Proxmox Baseline"
echo "  v1.2.1-linux-proxmox-baseline"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── Detect distro ─────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    VERSION="$VERSION_ID"
    echo "[info] Detected: $NAME $VERSION"
else
    DISTRO="unknown"
    echo "[warn] Could not detect distro, continuing with generic setup"
fi

# ── Install system dependencies ───────────────────────────────────
echo ""
echo "[1/6] Installing system dependencies..."

if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3 python3-pip python3-venv \
        git curl \
        libseccomp-dev 2>/dev/null || true
    # libseccomp-dev is optional — seccomp tests skip without it
elif command -v dnf &>/dev/null; then
    sudo dnf install -y python3 python3-pip git curl libseccomp-devel 2>/dev/null || true
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm python python-pip git curl libseccomp 2>/dev/null || true
else
    echo "[warn] Unknown package manager, skipping system deps"
fi

PYTHON_BIN=$(command -v python3 || command -v python)
echo "[ok] Python: $($PYTHON_BIN --version)"

# ── Clone or use existing ─────────────────────────────────────────
echo ""
echo "[2/6] Checking NodeChain source..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [ ! -f "$PROJECT_DIR/pyproject.toml" ]; then
    echo "[info] Cloning NodeChain..."
    git clone https://github.com/Alajmah/NodeChain.git /tmp/nodechain || {
        echo "[error] Could not clone. Please clone manually."
        exit 1
    }
    PROJECT_DIR="/tmp/nodechain"
fi

cd "$PROJECT_DIR"
echo "[ok] Project directory: $PROJECT_DIR"

# ── Create virtual environment ────────────────────────────────────
echo ""
echo "[3/6] Creating virtual environment..."

if [ ! -d ".venv" ]; then
    $PYTHON_BIN -m venv .venv
fi
source .venv/bin/activate
echo "[ok] Virtual environment active"

# ── Install Python dependencies ───────────────────────────────────
echo ""
echo "[4/6] Installing Python dependencies..."

pip install --upgrade pip -q
pip install -e ".[dev]" -q || pip install -e . -q

echo "[ok] Dependencies installed"

# ── Optional: seccomp Python bindings ──────────────────────────────
echo ""
echo "[5/6] Checking seccomp availability..."

SECCOMP_AVAILABLE=false
if pkg-config --exists libseccomp 2>/dev/null; then
    echo "[info] libseccomp detected — attempting Python bindings..."
    pip install seccomp -q 2>/dev/null && SECCOMP_AVAILABLE=true || {
        echo "[warn] seccomp Python bindings failed to install (optional)"
        echo "[warn] Linux sandbox tests will skip cleanly"
    }
else
    echo "[info] libseccomp not installed — seccomp tests will skip"
    echo "[info] Install with: sudo apt-get install libseccomp-dev"
fi

# ── Report environment ────────────────────────────────────────────
echo ""
echo "[6/6] Environment summary:"
echo "  Platform:   $(uname -srm)"
echo "  Kernel:     $(uname -r)"
echo "  Python:     $($PYTHON_BIN --version 2>&1)"
echo "  Seccomp:    $SECCOMP_AVAILABLE"
echo "  CGroups:    $(test -f /sys/fs/cgroup/cgroup.controllers && echo 'v2' || echo 'v1')"
echo "  Namespaces: $(test -f /proc/self/ns/mnt && echo 'available' || echo 'not detected')"
echo "  AppArmor:   $(test -d /sys/kernel/security/apparmor && echo 'available' || echo 'not detected')"

# ── Quick sanity check ────────────────────────────────────────────
echo ""
echo "Running quick sanity check..."
NODECHAIN_PROVIDER=mock $PYTHON_BIN -c "
from nodechain.sdk.os_sandbox import detect_backend, Platform
backend = detect_backend()
caps = backend.get_capabilities()
print(f'Backend: {backend.backend_name}')
print(f'Available: {backend.available}')
print(f'resource_limits_enforced: {caps.resource_limits_enforced}')
print(f'syscall_filtering_enforced: {caps.syscall_filtering_enforced}')
print(f'namespace_enforced: {caps.namespace_enforced}')
print(f'cgroup_enforced: {caps.cgroup_enforced}')
" 2>&1

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Next step: Run validation"
echo "    bash scripts/validate_linux.sh"
echo "══════════════════════════════════════════════════════════════"
