"""Tests for network policy enforcement at runtime.

AC1: socket.socket blocked for restricted trust levels.
AC2: socket.create_connection blocked.
AC3: urllib.request.urlopen blocked.
AC4: http.client connections blocked.
AC5: Built-in nodes retain network behavior if allowed.
AC6: NETWORK_POLICY_BLOCKED records api, host/port/url, node_id, trust_level.
AC7: Concurrent branch execution remains safe.
AC8: Existing 1012 tests remain green.

Skipped:
  test_symlink_escape_blocked — Windows symlink privilege limitation
"""

import asyncio
import http.client
import socket
import urllib.request
import pytest

from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.network_enforcer import (
    NetworkBlockedError, NetworkEnforcer, enforce_network_for_node,
    _active_network_enforcer,
)


class TestSocketSocket:
    """AC1: socket.socket blocked for restricted trust levels."""

    def test_socket_blocked_local_trusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            assert "socket.socket" in str(exc_info.value)

    def test_socket_blocked_local_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                socket.socket()

    def test_socket_blocked_remote_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                socket.socket()


class TestSocketCreateConnection:
    """AC2: socket.create_connection blocked."""

    def test_create_connection_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                socket.create_connection(("example.com", 80), timeout=0.1)
            assert "create_connection" in str(exc_info.value)
            assert exc_info.value.host == "example.com"

    def test_create_connection_blocked_trusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                socket.create_connection(("evil.com", 443), timeout=0.1)


class TestUrllibUrlopen:
    """AC3: urllib.request.urlopen blocked."""

    def test_urlopen_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                urllib.request.urlopen("http://example.com", timeout=0.1)
            assert "urlopen" in str(exc_info.value)
            assert "example.com" in str(exc_info.value)

    def test_urlopen_blocked_trusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                urllib.request.urlopen("https://evil.com", timeout=0.1)

    def test_urlopen_blocked_remote(self):
        enforcer = enforce_network_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                urllib.request.urlopen("http://data.leak", timeout=0.1)


class TestHttpClient:
    """AC4: http.client connections blocked."""

    def test_http_connection_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                http.client.HTTPConnection("example.com", 80)
            assert "HTTPConnection" in str(exc_info.value)

    def test_https_connection_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                http.client.HTTPSConnection("example.com", 443)
            assert "HTTPSConnection" in str(exc_info.value)

    def test_http_blocked_trusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                http.client.HTTPConnection("evil.com")


class TestBuiltinNetwork:
    """AC5: Built-in nodes retain network behavior."""

    def test_builtin_socket_allowed(self):
        enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            # Create a socket — should not raise
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            # Try connecting (will fail because no server, but should not be blocked)
            try:
                s.connect(("127.0.0.1", 1))
            except (OSError, ConnectionRefusedError):
                pass  # Expected — network is allowed but no server
            finally:
                s.close()


class TestErrorFormat:
    """AC6: NETWORK_POLICY_BLOCKED has all fields."""

    def test_error_fields(self):
        err = NetworkBlockedError(
            host="evil.com", port="443", url="",
            api="socket.create_connection",
            trust_level="local_untrusted",
            reason="network blocked",
            node_id="suspicious_node",
        )
        msg = str(err)
        assert "NETWORK_POLICY_BLOCKED" in msg
        assert "evil.com" in msg
        assert "create_connection" in msg
        assert "local_untrusted" in msg
        assert "suspicious_node" in msg

    def test_error_individual_fields(self):
        err = NetworkBlockedError(
            host="x.com", port="80", url="http://x.com",
            api="urlopen", trust_level="remote", reason="blocked", node_id="n1",
        )
        assert err.host == "x.com"
        assert err.port == "80"
        assert err.url == "http://x.com"
        assert err.api == "urlopen"
        assert err.node_id == "n1"


class TestEnforcementReport:
    """Report records network policy result."""

    def test_report_after_block(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        try:
            with enforcer.enforce():
                socket.socket()
        except NetworkBlockedError:
            pass
        report = enforcer.get_report()
        assert report["trust_level"] == "local_untrusted"
        assert report["violations"] >= 1
        assert report["allow_network"] is False
        entry = report["blocked_connections"][0]
        assert "api" in entry
        assert "trust_level" in entry

    def test_report_clean(self):
        enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.close()
        assert enforcer.get_report()["violations"] == 0


class TestHookRestoration:
    def test_cleared_after_exit(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "t")
        with enforcer.enforce():
            assert _active_network_enforcer.get() is enforcer
        assert _active_network_enforcer.get() is None

    def test_cleared_after_exception(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "t")
        try:
            with enforcer.enforce():
                socket.socket()
        except NetworkBlockedError:
            pass
        assert _active_network_enforcer.get() is None


class TestConcurrentNetwork:
    """AC7: Concurrent enforcement safe."""

    @pytest.mark.asyncio
    async def test_concurrent_different_trust_levels(self):
        results = {}

        async def restricted():
            enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "r")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    socket.socket()
                    results["restricted"] = "allowed"
                except NetworkBlockedError:
                    results["restricted"] = "blocked"

        async def builtin():
            enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.close()
                    results["builtin"] = "allowed"
                except NetworkBlockedError:
                    results["builtin"] = "blocked"

        await asyncio.gather(restricted(), builtin())
        assert results["restricted"] == "blocked"
        assert results["builtin"] == "allowed"
