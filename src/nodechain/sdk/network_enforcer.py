"""Network policy enforcement at runtime.

Intercepts network-related Python APIs during node execution to enforce
trust-level network restrictions. Uses contextvars for per-coroutine
isolation, consistent with import, filesystem, and subprocess enforcement.

Covers:
  - socket.socket, socket.create_connection
  - urllib.request.urlopen
  - http.client.HTTPConnection, HTTPSConnection

Does NOT cover (documented boundary for v0.5.x):
  - Raw ctypes/winsock calls
  - Already-captured socket objects
  - Third-party HTTP clients (requests, httpx) — import-blocked separately
  - DNS resolution via socket.getaddrinfo used indirectly
  - Threads/executors without context propagation
"""

from __future__ import annotations

import contextlib
import socket as _socket
import urllib.request as _urllib_request
import http.client as _http_client
from contextvars import ContextVar
from typing import Any, Generator

from nodechain.sdk.trust import TrustLevel, get_execution_policy


# Per-coroutine enforcement state
_active_network_enforcer: ContextVar["NetworkEnforcer | None"] = ContextVar(
    "nodechain_network_enforcer", default=None
)


class NetworkBlockedError(RuntimeError):
    """Raised when network access is blocked by trust policy."""

    def __init__(
        self,
        host: str = "",
        port: str = "",
        url: str = "",
        api: str = "",
        trust_level: str = "",
        reason: str = "",
        node_id: str = "",
    ):
        self.host = host
        self.port = port
        self.url = url
        self.api = api
        self.trust_level = trust_level
        self.reason = reason
        self.node_id = node_id
        target = url or f"{host}:{port}"
        super().__init__(
            f"NETWORK_POLICY_BLOCKED: '{target}' via {api} blocked by "
            f"{trust_level} trust policy (node={node_id}): {reason}"
        )


class NetworkEnforcer:
    """Enforces network policy during node execution."""

    def __init__(self, trust_level: TrustLevel, package_node_id: str = ""):
        self.trust_level = trust_level
        self.package_node_id = package_node_id
        self.policy = get_execution_policy(trust_level)
        self.blocked_connections: list[dict[str, str]] = []
        self._token = None

    def _check_network(self, api: str, host: str = "", port: str = "",
                       url: str = "") -> None:
        """Check if network access is allowed. Raises if blocked."""
        if self.trust_level == TrustLevel.BUILT_IN:
            if self.policy.allow_network:
                return

        if not self.policy.allow_network:
            record = {
                "api": api,
                "host": host,
                "port": str(port),
                "url": url,
                "trust_level": self.trust_level.value,
                "node_id": self.package_node_id,
                "reason": f"network blocked (allow_network={self.policy.allow_network})",
            }
            self.blocked_connections.append(record)
            raise NetworkBlockedError(
                host=host,
                port=str(port),
                url=url,
                api=api,
                trust_level=self.trust_level.value,
                reason=f"network blocked (trust={self.trust_level.value})",
                node_id=self.package_node_id,
            )

    @contextlib.contextmanager
    def enforce(self) -> Generator[None, None, None]:
        """Context manager that enforces network policy."""
        if self.trust_level == TrustLevel.BUILT_IN and self.policy.allow_network:
            yield
            return

        self._token = _active_network_enforcer.set(self)
        try:
            yield
        finally:
            _active_network_enforcer.reset(self._token)
            self._token = None

    @property
    def had_violations(self) -> bool:
        return len(self.blocked_connections) > 0

    def get_report(self) -> dict[str, Any]:
        return {
            "trust_level": self.trust_level.value,
            "node_id": self.package_node_id,
            "allow_network": self.policy.allow_network,
            "violations": len(self.blocked_connections),
            "blocked_connections": self.blocked_connections,
        }


# ── socket.socket patch ───────────────────────────────────────

_original_socket_init = _socket.socket.__init__


class _PatchedSocket(_socket.socket):
    """Patched socket that checks network policy."""

    def __init__(self, *args, **kwargs):
        enforcer = _active_network_enforcer.get()
        if enforcer is not None:
            enforcer._check_network(api="socket.socket")
        super().__init__(*args, **kwargs)


_socket.socket = _PatchedSocket  # type: ignore


# ── socket.create_connection patch ────────────────────────────

_original_create_connection = _socket.create_connection


def _patched_create_connection(address, *args, **kwargs):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        host, port = (str(address[0]), str(address[1])) if address else ("", "")
        enforcer._check_network(
            api="socket.create_connection", host=host, port=port,
        )
    return _original_create_connection(address, *args, **kwargs)


_socket.create_connection = _patched_create_connection  # type: ignore


# ── urllib.request.urlopen patch ──────────────────────────────

_original_urlopen = _urllib_request.urlopen


def _patched_urlopen(url, *args, **kwargs):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        url_str = str(url)
        # Extract host from url
        host = ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url_str)
            host = parsed.hostname or ""
        except Exception:
            pass
        enforcer._check_network(api="urllib.request.urlopen", url=url_str, host=host)
    return _original_urlopen(url, *args, **kwargs)


_urllib_request.urlopen = _patched_urlopen  # type: ignore


# ── http.client patches ───────────────────────────────────────

_original_http_init = _http_client.HTTPConnection.__init__
_original_https_init = _http_client.HTTPSConnection.__init__


class _PatchedHTTPConnection(_http_client.HTTPConnection):
    def __init__(self, host, port=None, *args, **kwargs):
        enforcer = _active_network_enforcer.get()
        if enforcer is not None:
            enforcer._check_network(
                api="http.client.HTTPConnection",
                host=str(host), port=str(port or ""),
            )
        super().__init__(host, port, *args, **kwargs)


class _PatchedHTTPSConnection(_http_client.HTTPSConnection):
    def __init__(self, host, port=None, *args, **kwargs):
        enforcer = _active_network_enforcer.get()
        if enforcer is not None:
            enforcer._check_network(
                api="http.client.HTTPSConnection",
                host=str(host), port=str(port or ""),
            )
        super().__init__(host, port, *args, **kwargs)


_http_client.HTTPConnection = _PatchedHTTPConnection  # type: ignore
_http_client.HTTPSConnection = _PatchedHTTPSConnection  # type: ignore


# ── DNS helper patches ───────────────────────────────────────

_original_getaddrinfo = _socket.getaddrinfo
_original_gethostbyname = _socket.gethostbyname
_original_gethostbyaddr = _socket.gethostbyaddr


def _patched_getaddrinfo(host, port=None, *args, **kwargs):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(
            api="socket.getaddrinfo", host=str(host), port=str(port or ""),
        )
    return _original_getaddrinfo(host, port, *args, **kwargs)


def _patched_gethostbyname(host):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(api="socket.gethostbyname", host=str(host))
    return _original_gethostbyname(host)


def _patched_gethostbyaddr(ip):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(api="socket.gethostbyaddr", host=str(ip))
    return _original_gethostbyaddr(ip)


_socket.getaddrinfo = _patched_getaddrinfo  # type: ignore
_socket.gethostbyname = _patched_gethostbyname  # type: ignore
_socket.gethostbyaddr = _patched_gethostbyaddr  # type: ignore


# ── SSL patches ──────────────────────────────────────────────

import ssl as _ssl

_original_ssl_wrap_socket = getattr(_ssl, "wrap_socket", None)
_original_sslcontext_wrap = _ssl.SSLContext.wrap_socket


def _patched_ssl_wrap_socket(sock, *args, **kwargs):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(api="ssl.wrap_socket")
    return _original_ssl_wrap_socket(sock, *args, **kwargs)


def _patched_sslcontext_wrap(self, sock, *args, **kwargs):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(api="ssl.SSLContext.wrap_socket")
    return _original_sslcontext_wrap(self, sock, *args, **kwargs)


if _original_ssl_wrap_socket is not None:
    _ssl.wrap_socket = _patched_ssl_wrap_socket  # type: ignore
_ssl.SSLContext.wrap_socket = _patched_sslcontext_wrap  # type: ignore


# ── urllib opener patches ────────────────────────────────────

_original_build_opener = _urllib_request.build_opener
_original_install_opener = _urllib_request.install_opener


def _patched_build_opener(*handlers):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(api="urllib.request.build_opener")
    return _original_build_opener(*handlers)


def _patched_install_opener(opener):
    enforcer = _active_network_enforcer.get()
    if enforcer is not None:
        enforcer._check_network(api="urllib.request.install_opener")
    return _original_install_opener(opener)


_urllib_request.build_opener = _patched_build_opener  # type: ignore
_urllib_request.install_opener = _patched_install_opener  # type: ignore


def enforce_network_for_node(
    trust_level: TrustLevel,
    node_id: str,
) -> NetworkEnforcer:
    """Create a network enforcer for a node execution."""
    return NetworkEnforcer(trust_level, node_id)
