"""Search adapter failure taxonomy and structured failure objects (v2.57.0).

Classifies adapter failures into typed categories so that SearchToolNode,
trace events, and eval reports can distinguish timeout from rate-limit
from schema drift instead of recording generic string errors.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel


class SearchFailureType(str, Enum):
    """Typed failure categories for search adapter operations."""

    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    HTTP_ERROR = "http_error"
    SCHEMA_DRIFT = "schema_drift"
    EMPTY_RESULT = "empty_result"
    MALFORMED_PAYLOAD = "malformed_payload"
    CIRCUIT_OPEN = "circuit_open"
    UNKNOWN = "unknown"


# Failure types that should be retried (transient).
RETRYABLE_FAILURE_TYPES = {
    SearchFailureType.TIMEOUT,
    SearchFailureType.RATE_LIMIT,
    SearchFailureType.HTTP_ERROR,  # 5xx only; 4xx classified separately
}

# Failure types that should NOT be retried (deterministic).
NON_RETRYABLE_FAILURE_TYPES = {
    SearchFailureType.SCHEMA_DRIFT,
    SearchFailureType.MALFORMED_PAYLOAD,
    SearchFailureType.EMPTY_RESULT,
    SearchFailureType.CIRCUIT_OPEN,
}


class AdapterFailure(BaseModel):
    """Structured adapter failure record for trace/output visibility."""

    adapter: str
    failure_type: SearchFailureType
    retryable: bool
    attempts: int = 1
    status_code: int | None = None
    latency_ms: int = 0
    query_hash: str = ""
    message: str = ""
    exception_class: str = ""
    timestamp: str = ""
    reason_code: str = ""

    model_config = {"extra": "allow"}

    def __init__(self, **data: Any) -> None:
        if not data.get("timestamp"):
            data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Derive retryable from failure_type if not explicitly set
        if "retryable" not in data:
            ft = data.get("failure_type", SearchFailureType.UNKNOWN)
            if isinstance(ft, str):
                ft = SearchFailureType(ft)
            data["retryable"] = ft in RETRYABLE_FAILURE_TYPES
        super().__init__(**data)


class SearchFetchResult(BaseModel):
    """Result from the shared _fetch() helper.

    Either data is present (success) or failure is present (error).
    """

    data: dict[str, Any] | None = None
    text: str | None = None
    failure: AdapterFailure | None = None
    latency_ms: int = 0
    attempts: int = 1

    @property
    def succeeded(self) -> bool:
        return self.failure is None


def classify_exception(
    exc: Exception,
    adapter_name: str,
    status_code: int | None = None,
) -> SearchFailureType:
    """Classify an exception into a SearchFailureType.

    Uses exception type and status code to determine the failure category.
    """
    exc_name = type(exc).__name__

    # httpx timeout variants
    if "timeout" in exc_name.lower() or "Timeout" in exc_name:
        return SearchFailureType.TIMEOUT

    # httpx connect errors → treat as timeout (transient network)
    if "ConnectError" in exc_name or "ReadError" in exc_name:
        return SearchFailureType.TIMEOUT

    # HTTP status-based classification
    if status_code is not None:
        if status_code == 429:
            return SearchFailureType.RATE_LIMIT
        if 500 <= status_code < 600:
            return SearchFailureType.HTTP_ERROR
        if 400 <= status_code < 500:
            # Client errors are generally not retryable
            # but we classify as HTTP_ERROR for visibility
            return SearchFailureType.HTTP_ERROR

    # JSON/parse errors
    if "JSONDecodeError" in exc_name or "JSON" in exc_name or "DecodeError" in exc_name:
        return SearchFailureType.MALFORMED_PAYLOAD

    # ValueError with "json" in message → likely a parse error
    if isinstance(exc, ValueError) and "json" in str(exc).lower():
        return SearchFailureType.MALFORMED_PAYLOAD

    # XML parse errors
    if "ParseError" in exc_name or "ParseSyntax" in exc_name:
        return SearchFailureType.MALFORMED_PAYLOAD

    # KeyError/TypeError on response → schema drift
    if isinstance(exc, (KeyError, TypeError, AttributeError)):
        return SearchFailureType.SCHEMA_DRIFT

    return SearchFailureType.UNKNOWN


def classify_http_status(status_code: int) -> SearchFailureType | None:
    """Classify an HTTP status code. Returns None for success (2xx)."""
    if 200 <= status_code < 300:
        return None
    if status_code == 429:
        return SearchFailureType.RATE_LIMIT
    if 500 <= status_code < 600:
        return SearchFailureType.HTTP_ERROR
    if 400 <= status_code < 500:
        return SearchFailureType.HTTP_ERROR
    return SearchFailureType.UNKNOWN
