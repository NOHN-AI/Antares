"""Federation — signed domain descriptors and cross-domain routing.
Provides:
  - DomainDescriptor with Ed25519 signature over canonical CBOR
  - descriptor version monotonicity and validity-window checks
  - route queries with visited-domain loop detection and hop limits

The registry verifies signatures against locally configured trust anchors.
This module does not open sockets.
"""
import time
from dataclasses import dataclass, field
from typing import Optional

from .cbor_utils import encode_deterministic
from .signing import sign as ed25519_sign, verify as ed25519_verify
from .types import (
    SPEC_VERSION,
    ALG_ED25519,
    ErrorCode,
    MAX_ROUTE_HOPS,
)


@dataclass
class TrustAnchor:
    key_id: str
    algorithm: str
    public_key: bytes  # raw 32-byte Ed25519 public key


@dataclass
class Gateway:
    uri: str
    transport: str          # "http3", "a2a", "tcp+tls", ...
    priority: int
    profiles: list = field(default_factory=list)


@dataclass
class DomainDescriptor:
    domain_id: str
    descriptor_version: int
    valid_from: float
    valid_until: float
    gateways: list = field(default_factory=list)
    services: list = field(default_factory=list)
    trust_anchors: list = field(default_factory=list)
    revocation_endpoints: list = field(default_factory=list)
    signature_algorithm: str = ALG_ED25519
    signature: str = ""

    def is_valid_now(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return self.valid_from <= now <= self.valid_until


class FederationError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def descriptor_canonical_bytes(desc: DomainDescriptor) -> bytes:
    """Deterministic bytes covered by the descriptor signature."""
    return encode_deterministic({
        "ver": SPEC_VERSION,
        "dom": desc.domain_id,
        "dv": desc.descriptor_version,
        "vf": desc.valid_from,
        "vu": desc.valid_until,
        "gw": [
            {
                "uri": g.uri,
                "tr": g.transport,
                "pr": g.priority,
                "pf": g.profiles,
            } for g in desc.gateways
        ],
        "sv": desc.services,
        "ta": [
            {
                "kid": t.key_id,
                "alg": t.algorithm,
                "pub": t.public_key,
            } for t in desc.trust_anchors
        ],
        "rev": desc.revocation_endpoints,
        "alg": desc.signature_algorithm,
    })


def sign_descriptor(desc: DomainDescriptor,
                    private_key: bytes) -> DomainDescriptor:
    """Sign a descriptor in place with the domain's Ed25519 private key."""
    desc.signature_algorithm = ALG_ED25519
    desc.signature = ed25519_sign(
        private_key, descriptor_canonical_bytes(desc)
    ).hex()
    return desc


class FederationRegistry:
    """Local registry of verified remote domains."""

    def __init__(self, local_domain_id: str):
        self.local_domain_id = local_domain_id
        self._descriptors: dict[str, DomainDescriptor] = {}
        self._trust_anchors: dict[str, bytes] = {}

    def add_trust_anchor(self, domain_id: str, public_key: bytes) -> None:
        """Register the root public key expected for a domain."""
        self._trust_anchors[domain_id] = public_key

    def register(self, desc: DomainDescriptor) -> None:
        if not desc.is_valid_now():
            raise FederationError(
                ErrorCode.DESCRIPTOR_EXPIRED,
                f"descriptor expired for {desc.domain_id}",
            )

        if desc.domain_id in self._descriptors:
            existing = self._descriptors[desc.domain_id]
            if desc.descriptor_version <= existing.descriptor_version:
                raise FederationError(
                    ErrorCode.DESCRIPTOR_VERSION_STALE,
                    "descriptor version must increase",
                )

        public_key = self._trust_anchors.get(desc.domain_id)
        if public_key is None:
            raise FederationError(
                ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                f"no trust anchor for {desc.domain_id}",
            )
        try:
            signature = bytes.fromhex(desc.signature)
        except (ValueError, TypeError):
            raise FederationError(
                ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                "malformed descriptor signature",
            )
        if not ed25519_verify(
            public_key, descriptor_canonical_bytes(desc), signature
        ):
            raise FederationError(
                ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                "descriptor signature verification failed",
            )

        self._descriptors[desc.domain_id] = desc

    def route_query(self, *, target_domain: str,
                    visited_domains: list,
                    max_hops: int = MAX_ROUTE_HOPS) -> dict:
        """Resolve the next gateway for a target domain.

        Enforces hop limits and visited-domain loop detection.
        """
        if max_hops <= 0:
            raise FederationError(
                ErrorCode.ROUTE_HOP_LIMIT, "max_hops reached 0"
            )
        if self.local_domain_id in visited_domains:
            raise FederationError(
                ErrorCode.ROUTE_LOOP, "route loop detected"
            )

        desc = self._descriptors.get(target_domain)
        if desc is None:
            return {"status": "unknown", "next_hop": None}

        gateways = sorted(desc.gateways, key=lambda g: g.priority)
        return {
            "status": "resolved",
            "next_hop": gateways[0].uri if gateways else None,
            "domain": target_domain,
        }

    def get(self, domain_id: str) -> Optional[DomainDescriptor]:
        return self._descriptors.get(domain_id)

    def count(self) -> int:
        return len(self._descriptors)
