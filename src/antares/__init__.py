"""Antares — audit and federation layer for AI agents.

Two capabilities:
  - Audit: signed causal events with cycle detection
  - Federation: signed domain descriptors with cross-domain routing

Transport is out of scope: carry Antares messages over HTTP/3, A2A, MCP,
or any authenticated channel.
"""
from .types import SPEC_VERSION, ErrorCode, MAX_PARENT_EVENTS, MAX_ROUTE_HOPS
from .cbor_utils import encode_deterministic, decode
from .signing import (
    generate_keypair,
    sign,
    verify,
    key_id_for,
    TrustAnchorRegistry,
)
from .audit import AuditLog, AuditEvent, AuditError
from .federation import (
    FederationRegistry,
    DomainDescriptor,
    Gateway,
    TrustAnchor,
    FederationError,
    sign_descriptor,
    descriptor_canonical_bytes,
)
from .business import BusinessHandler, SimpleKVStore, state_hash

__version__ = "2.0.0"

__all__ = [
    "SPEC_VERSION",
    "ErrorCode",
    "MAX_PARENT_EVENTS",
    "MAX_ROUTE_HOPS",
    "encode_deterministic",
    "decode",
    "generate_keypair",
    "sign",
    "verify",
    "key_id_for",
    "TrustAnchorRegistry",
    "AuditLog",
    "AuditEvent",
    "AuditError",
    "FederationRegistry",
    "DomainDescriptor",
    "Gateway",
    "TrustAnchor",
    "FederationError",
    "sign_descriptor",
    "descriptor_canonical_bytes",
    "BusinessHandler",
    "SimpleKVStore",
    "state_hash",
]
