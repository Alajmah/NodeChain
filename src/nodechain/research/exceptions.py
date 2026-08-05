"""Custom exceptions for the ResearchWorkspaceBundleV1 implementation."""

from __future__ import annotations


class BundleError(Exception):
    """Base class for all research bundle errors."""


class BundleFinalizationError(BundleError):
    """Raised when a bundle cannot be finalized (e.g. write failure, partial
    state, or an existing finalized bundle would be overwritten)."""


class BundleValidationError(BundleError):
    """Raised when a bundle document fails JSON schema validation or a
    cross-reference integrity check."""


class BundleIntegrityError(BundleError):
    """Raised when a finalized bundle's recorded file hashes do not match the
    artifacts on disk, or when the manifest self-hash cannot be reproduced."""
