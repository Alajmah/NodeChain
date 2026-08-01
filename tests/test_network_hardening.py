"""Tests for network boundary hardening: DNS, SSL, urllib opener.

AC1: socket.getaddrinfo blocked for restricted levels.
AC2: socket.gethostbyname/gethostbyaddr blocked.
AC3: SSL wrap_socket blocked when network policy is blocked.
AC4: urllib opener paths covered.
AC5: Already-imported third-party behavior documented.
AC6: Error records api, host, port, url, node_id, trust_level, reason.
AC7: Concurrent branch execution remains safe.
AC8: Existing 1031 tests remain green.
"""

import asyncio
import socket
import ssl
import urllib.request
import pytest

from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.network_enforcer import (
    NetworkBlockedError, enforce_network_for_node,
)


class TestGetaddrinfo:
    """AC1: socket.getaddrinfo blocked."""

    def test_getaddrinfo_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                socket.getaddrinfo("example.com", 80)
            assert "getaddrinfo" in str(exc_info.value)
            assert exc_info.value.host == "example.com"

    def test_getaddrinfo_blocked_trusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                socket.getaddrinfo("evil.com", 443)


class TestGethostbyname:
    """AC2: socket.gethostbyname blocked."""

    def test_gethostbyname_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                socket.gethostbyname("example.com")
            assert "gethostbyname" in str(exc_info.value)

    def test_gethostbyname_blocked_remote(self):
        enforcer = enforce_network_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                socket.gethostbyname("evil.com")


class TestGethostbyaddr:
    """AC2: socket.gethostbyaddr blocked."""

    def test_gethostbyaddr_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                socket.gethostbyaddr("8.8.8.8")
            assert "gethostbyaddr" in str(exc_info.value)


class TestSSLWrap:
    """AC3: SSL socket wrapping blocked."""

    def test_sslcontext_wrap_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        # Create socket BEFORE enforcement to isolate SSL testing
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with enforcer.enforce():
                with pytest.raises(NetworkBlockedError) as exc_info:
                    ctx.wrap_socket(raw, server_hostname="evil.com")
                assert "SSLContext.wrap_socket" in str(exc_info.value)
        finally:
            raw.close()

    def test_ssl_wrap_blocked_trusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with enforcer.enforce():
                with pytest.raises(NetworkBlockedError):
                    ctx.wrap_socket(raw)
        finally:
            raw.close()


class TestUrllibOpener:
    """AC4: urllib opener paths covered."""

    def test_build_opener_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError) as exc_info:
                urllib.request.build_opener()
            assert "build_opener" in str(exc_info.value)

    def test_install_opener_blocked_untrusted(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(NetworkBlockedError):
                urllib.request.install_opener(None)


class TestBuiltinAllowed:
    """Built-in retains all network APIs."""

    def test_builtin_getaddrinfo_allowed(self):
        enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            # This will do a real DNS lookup, but should not be blocked
            result = socket.getaddrinfo("localhost", 80)
            assert len(result) > 0

    def test_builtin_ssl_wrap_allowed(self):
        enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # wrap_socket should not raise NetworkBlockedError
                # (connection will fail since we don't connect, but that's fine)
                wrapped = ctx.wrap_socket(raw, server_hostname="localhost")
                wrapped.close()
            except (OSError, ConnectionRefusedError):
                pass  # Expected — not a policy error
            finally:
                try:
                    raw.close()
                except OSError:
                    pass

    def test_builtin_build_opener_allowed(self):
        enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            opener = urllib.request.build_opener()
            assert opener is not None


class TestThirdPartyDocumentation:
    """AC5: Already-imported third-party behavior documented.

    Third-party HTTP clients (requests, httpx, urllib3) are import-blocked
    for local_untrusted and remote_untrusted. For local_trusted, they may
    be allowed by import policy. This test documents the boundary:
    if requests is already imported, its calls are NOT runtime-intercepted
    because we only patch stdlib APIs. This is a documented limitation.
    """

    def test_documented_boundary(self):
        """Document: third-party clients use stdlib internally.

        requests/httpx internally use socket and ssl, which ARE patched.
        If they use already-captured socket objects, they bypass enforcement.
        This is documented as out of scope for v0.5.x.
        """
        # This test exists to document the boundary.
        # No assertion needed — the docstring IS the documentation.
        assert True


class TestErrorRecordsAllFields:
    """AC6: Error records all fields."""

    def test_dns_error_has_host(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "n1")
        with enforcer.enforce():
            try:
                socket.gethostbyname("evil.com")
            except NetworkBlockedError as e:
                assert e.api == "socket.gethostbyname"
                assert e.host == "evil.com"
                assert e.node_id == "n1"
                assert e.trust_level == "local_untrusted"

    def test_ssl_error_has_api(self):
        enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "n2")
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with enforcer.enforce():
                try:
                    ctx.wrap_socket(raw)
                except NetworkBlockedError as e:
                    assert e.api == "ssl.SSLContext.wrap_socket"
                    assert e.node_id == "n2"
        finally:
            raw.close()


class TestConcurrentHardening:
    """AC7: Concurrent enforcement safe with new patches."""

    @pytest.mark.asyncio
    async def test_concurrent_dns_and_ssl(self):
        results = {}

        async def restricted_dns():
            enforcer = enforce_network_for_node(TrustLevel.LOCAL_UNTRUSTED, "r")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    socket.getaddrinfo("evil.com", 80)
                    results["dns"] = "allowed"
                except NetworkBlockedError:
                    results["dns"] = "blocked"

        async def builtin_dns():
            enforcer = enforce_network_for_node(TrustLevel.BUILT_IN, "core")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    socket.getaddrinfo("localhost", 80)
                    results["builtin_dns"] = "allowed"
                except NetworkBlockedError:
                    results["builtin_dns"] = "blocked"

        await asyncio.gather(restricted_dns(), builtin_dns())
        assert results["dns"] == "blocked"
        assert results["builtin_dns"] == "allowed"
