"""Federation — signed domain descriptors, trust anchors, routing (spec §12).

Hardening in 2.1:
  - descriptors travel in the signed envelope: domain, version, validity,
    gateways, anchors and revocations are all covered by one signature
  - key rotation needs a pre-commitment: the outgoing anchor signs
    `next_key_hash` over the successor key, so rotation is not trust-on-
    first-use
  - gateways may carry a proof of possession; an unproven gateway is
    reported instead of being silently trusted
  - revocation entries are signed inside the descriptor and are evaluated at
    the claimed observation time, not only "now"

The registry verifies signatures against locally configured anchors. This
module does not open sockets.
"""
import time
from dataclasses import dataclass, field
from typing import Optional

from .cbor_utils import encode_deterministic
from .envelope import Envelope, EnvelopeError
from .merkle import digest_hex, sha256
from .signing import key_id_for, public_key_from_wire, public_key_wire
from .types import (
    ALG_ED25519,
    ErrorCode,
    MAX_ROUTE_HOPS,
    MSG_DESCRIPTOR,
    MSG_GATEWAY_POP,
)

DESCRIPTOR_KEYS = ("dom", "dv", "vf", "vu", "gw", "sv", "ta", "rev")
GATEWAY_KEYS = ("uri", "tr", "pr", "pf", "pop")
ANCHOR_KEYS = ("kid", "alg", "pk", "vf", "vu", "nx")
REVOCATION_KEYS = ("kid", "at", "rs")
POP_KEYS = ("dom", "dv", "uri", "tr")

KEY_TAG = b"antares.key.v1"


class FederationError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def key_fingerprint(public_key, algorithm: str = ALG_ED25519) -> str:
    """Stable fingerprint used as a rotation pre-commitment."""
    wire = public_key_wire(algorithm, public_key)
    return digest_hex(sha256(KEY_TAG + encode_deterministic(wire)))


@dataclass
class TrustAnchor:
    key_id: str
    algorithm: str
    public_key: object            # raw 32 bytes, or {component: bytes}
    valid_from: float = 0.0
    valid_until: float = 0.0      # 0.0 = no expiry
    next_key_hash: str = ""       # fingerprint of the successor key

    def is_valid_now(self, now: float = None) -> bool:
        now = time.time() if now is None else now
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        return True

    def to_wire(self) -> dict:
        return {
            "kid": self.key_id,
            "alg": self.algorithm,
            "pk": public_key_wire(self.algorithm, self.public_key),
            "vf": float(self.valid_from),
            "vu": float(self.valid_until),
            "nx": self.next_key_hash,
        }

    @classmethod
    def from_wire(cls, wire: dict) -> "TrustAnchor":
        if set(wire) != set(ANCHOR_KEYS):
            raise FederationError(ErrorCode.BODY_INVALID,
                                  "anchor key set invalid")
        return cls(
            key_id=wire["kid"],
            algorithm=wire["alg"],
            public_key=public_key_from_wire(wire["pk"]),
            valid_from=wire["vf"],
            valid_until=wire["vu"],
            next_key_hash=wire["nx"],
        )


@dataclass
class RevocationEntry:
    key_id: str
    revoked_at: float
    reason: str = ""

    def to_wire(self) -> dict:
        return {"kid": self.key_id, "at": float(self.revoked_at),
                "rs": self.reason}

    @classmethod
    def from_wire(cls, wire: dict) -> "RevocationEntry":
        if set(wire) != set(REVOCATION_KEYS):
            raise FederationError(ErrorCode.BODY_INVALID,
                                  "revocation key set invalid")
        return cls(key_id=wire["kid"], revoked_at=wire["at"],
                   reason=wire["rs"])


@dataclass
class Gateway:
    uri: str
    transport: str          # "http3", "a2a", "tcp+tls", ...
    priority: int
    profiles: list = field(default_factory=list)
    pop: Optional[dict] = None   # proof-of-possession wire map

    def pop_key_id(self) -> str:
        return self.pop.get("k", "") if isinstance(self.pop, dict) else ""

    def to_wire(self) -> dict:
        return {
            "uri": self.uri,
            "tr": self.transport,
            "pr": int(self.priority),
            "pf": list(self.profiles),
            "pop": self.pop,
        }

    @classmethod
    def from_wire(cls, wire: dict) -> "Gateway":
        if set(wire) != set(GATEWAY_KEYS):
            raise FederationError(ErrorCode.BODY_INVALID,
                                  "gateway key set invalid")
        return cls(uri=wire["uri"], transport=wire["tr"],
                   priority=wire["pr"], profiles=list(wire["pf"]),
                   pop=wire["pop"])


def gateway_pop_bytes(domain_id: str, version: int, uri: str,
                      transport: str) -> bytes:
    return encode_deterministic({
        "dom": domain_id, "dv": int(version), "uri": uri, "tr": transport,
    })


def sign_gateway_pop(gateway: Gateway, *, domain_id: str,
                     descriptor_version: int, private_key,
                     key_id: str, alg: str = ALG_ED25519) -> dict:
    """Prove control of the key that speaks for this gateway URI."""
    env = Envelope(
        msg=MSG_GATEWAY_POP,
        body={"dom": domain_id, "dv": int(descriptor_version),
              "uri": gateway.uri, "tr": gateway.transport},
        ctx=domain_id.encode("utf-8"),
        key_id=key_id,
        alg=alg,
    )
    env.sign(private_key, key_id=key_id)
    gateway.pop = env.to_wire()
    return gateway.pop


def verify_gateway_pop(gateway: Gateway, public_key, *, domain_id: str,
                       descriptor_version: int) -> bool:
    if not isinstance(gateway.pop, dict):
        return False
    try:
        env = Envelope.from_wire(gateway.pop)
    except EnvelopeError:
        return False
    if env.msg != MSG_GATEWAY_POP or set(env.body) != set(POP_KEYS):
        return False
    if env.body["dom"] != domain_id or \
            env.body["dv"] != int(descriptor_version) or \
            env.body["uri"] != gateway.uri or \
            env.body["tr"] != gateway.transport:
        return False
    return env.verify(public_key, expect_msg=MSG_GATEWAY_POP)


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
    signing_key_id: str = ""
    revocations: list = field(default_factory=list)  # RevocationEntry

    def is_valid_now(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return self.valid_from <= now <= self.valid_until

    def to_body(self) -> dict:
        return {
            "dom": self.domain_id,
            "dv": int(self.descriptor_version),
            "vf": float(self.valid_from),
            "vu": float(self.valid_until),
            "gw": [g.to_wire() for g in self.gateways],
            "sv": list(self.services),
            "ta": [t.to_wire() for t in self.trust_anchors],
            "rev": [r.to_wire() for r in self.revocations],
        }

    def to_envelope(self) -> Envelope:
        return Envelope(
            msg=MSG_DESCRIPTOR,
            body=self.to_body(),
            ctx=self.domain_id.encode("utf-8"),
            key_id=self.signing_key_id or key_id_for(self.domain_id),
            alg=self.signature_algorithm,
            signature=self.signature,
        )

    def to_wire(self) -> dict:
        return self.to_envelope().to_wire()

    @classmethod
    def from_wire(cls, wire: dict) -> "DomainDescriptor":
        env = Envelope.from_wire(wire)
        if env.msg != MSG_DESCRIPTOR:
            raise FederationError(ErrorCode.BODY_INVALID,
                                  f"expected {MSG_DESCRIPTOR}")
        body = env.body
        if set(body) != set(DESCRIPTOR_KEYS):
            raise FederationError(ErrorCode.BODY_INVALID,
                                  "descriptor body key set invalid")
        return cls(
            domain_id=body["dom"],
            descriptor_version=body["dv"],
            valid_from=body["vf"],
            valid_until=body["vu"],
            gateways=[Gateway.from_wire(g) for g in body["gw"]],
            services=list(body["sv"]),
            trust_anchors=[TrustAnchor.from_wire(t) for t in body["ta"]],
            revocation_endpoints=[],
            signature_algorithm=env.alg,
            signature=env.signature,
            signing_key_id=env.key_id,
            revocations=[RevocationEntry.from_wire(r) for r in body["rev"]],
        )


def descriptor_canonical_bytes(desc: DomainDescriptor) -> bytes:
    """Deterministic bytes covered by the descriptor signature."""
    return desc.to_envelope().signed_bytes()


def sign_descriptor(desc: DomainDescriptor, private_key,
                    key_id: str = "") -> DomainDescriptor:
    """Sign a descriptor in place with the domain's signing key."""
    env = Envelope(
        msg=MSG_DESCRIPTOR,
        body=desc.to_body(),
        ctx=desc.domain_id.encode("utf-8"),
        key_id=key_id or desc.signing_key_id or key_id_for(desc.domain_id),
        alg=desc.signature_algorithm,
    )
    env.sign(private_key, key_id=env.key_id)
    desc.signature_algorithm = env.alg
    desc.signing_key_id = env.key_id
    desc.signature = env.signature
    return desc


class FederationRegistry:
    """Local registry of verified remote domains."""

    def __init__(self, local_domain_id: str):
        self.local_domain_id = local_domain_id
        self._descriptors: dict = {}
        self._anchors: dict = {}
        self._warnings: dict = {}

    # ── anchors ────────────────────────────────────────────
    def add_trust_anchor(self, domain_id: str, public_key,
                         key_id: str = "",
                         algorithm: str = ALG_ED25519,
                         next_key_hash: str = "",
                         valid_from: float = 0.0,
                         valid_until: float = 0.0) -> TrustAnchor:
        anchor = TrustAnchor(
            key_id=key_id or key_id_for(domain_id),
            algorithm=algorithm,
            public_key=public_key,
            valid_from=valid_from,
            valid_until=valid_until,
            next_key_hash=next_key_hash,
        )
        self._anchors[domain_id] = anchor
        return anchor

    def rotate_anchor(self, domain_id: str, public_key, key_id: str = "",
                      algorithm: str = ALG_ED25519,
                      force: bool = False) -> TrustAnchor:
        """Rotate to a new key, requiring the old anchor's pre-commitment."""
        anchor = self._anchors.get(domain_id)
        if anchor is None:
            raise FederationError(ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                                  "no trust anchor to rotate from")
        expected = key_fingerprint(public_key, algorithm)
        if not force and anchor.next_key_hash != expected:
            raise FederationError(
                ErrorCode.ROTATION_UNPROVEN,
                "the outgoing anchor did not pre-commit to this key",
            )
        return self.add_trust_anchor(domain_id, public_key, key_id=key_id,
                                     algorithm=algorithm)

    def anchor(self, domain_id: str) -> Optional[TrustAnchor]:
        return self._anchors.get(domain_id)

    def warnings(self, domain_id: str) -> list:
        return list(self._warnings.get(domain_id, []))

    # ── revocation ─────────────────────────────────────────
    def is_revoked(self, domain_id: str, key_id: str,
                   at: Optional[float] = None) -> bool:
        desc = self._descriptors.get(domain_id)
        if desc is None:
            return False
        when = time.time() if at is None else at
        for entry in desc.revocations:
            if entry.key_id == key_id and when >= entry.revoked_at:
                return True
        return False

    # ── register ───────────────────────────────────────────
    def register(self, desc: DomainDescriptor, gateway_keys: dict = None,
                 require_pop: bool = False) -> None:
        now = time.time()
        if not desc.is_valid_now(now):
            raise FederationError(
                ErrorCode.DESCRIPTOR_EXPIRED,
                f"descriptor expired for {desc.domain_id}",
            )
        existing = self._descriptors.get(desc.domain_id)
        if existing is not None and \
                desc.descriptor_version <= existing.descriptor_version:
            raise FederationError(
                ErrorCode.DESCRIPTOR_VERSION_STALE,
                "descriptor version must increase",
            )

        anchor = self._anchors.get(desc.domain_id)
        if anchor is None:
            raise FederationError(
                ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                f"no trust anchor for {desc.domain_id}",
            )

        signer_id = desc.signing_key_id or key_id_for(desc.domain_id)
        rotated = False
        candidate = None
        if signer_id == anchor.key_id:
            public_key = anchor.public_key
        else:
            candidate = next(
                (t for t in desc.trust_anchors if t.key_id == signer_id),
                None,
            )
            if candidate is None:
                raise FederationError(
                    ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                    "descriptor signed by a key absent from trust_anchors",
                )
            expected = key_fingerprint(candidate.public_key,
                                       candidate.algorithm)
            if anchor.next_key_hash and \
                    anchor.next_key_hash == expected:
                public_key = candidate.public_key
                rotated = True
            else:
                raise FederationError(
                    ErrorCode.ROTATION_UNPROVEN,
                    "descriptor key is neither the anchor nor a "
                    "pre-committed successor",
                )

        if not desc.to_envelope().verify(
                public_key, expect_msg=MSG_DESCRIPTOR,
                expect_ctx=desc.domain_id.encode("utf-8")):
            raise FederationError(
                ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
                "descriptor signature verification failed",
            )

        for entry in desc.revocations:
            if entry.key_id == signer_id and now >= entry.revoked_at:
                raise FederationError(
                    ErrorCode.REVOKED_KEY,
                    f"descriptor signed by revoked key {signer_id}",
                )

        warnings = []
        keys = dict(gateway_keys or {})
        for gateway in desc.gateways:
            if gateway.pop is None:
                if require_pop:
                    raise FederationError(
                        ErrorCode.GATEWAY_UNPROVEN,
                        f"gateway {gateway.uri} has no proof of possession",
                    )
                warnings.append(f"gateway {gateway.uri} unproven")
                continue
            pop_key = keys.get(gateway.pop_key_id())
            if pop_key is None:
                if require_pop:
                    raise FederationError(
                        ErrorCode.GATEWAY_UNPROVEN,
                        f"no key for gateway proof {gateway.uri}",
                    )
                warnings.append(
                    f"gateway {gateway.uri} proof not checkable "
                    f"(unknown key)"
                )
                continue
            if not verify_gateway_pop(
                    gateway, pop_key,
                    domain_id=desc.domain_id,
                    descriptor_version=desc.descriptor_version):
                raise FederationError(
                    ErrorCode.GATEWAY_UNPROVEN,
                    f"gateway proof invalid for {gateway.uri}",
                )

        if rotated and candidate is not None:
            self._anchors[desc.domain_id] = TrustAnchor(
                key_id=candidate.key_id,
                algorithm=candidate.algorithm,
                public_key=candidate.public_key,
            )
            warnings.append("trust anchor rotated via pre-commitment")

        self._descriptors[desc.domain_id] = desc
        self._warnings[desc.domain_id] = warnings

    # ── verification helpers ───────────────────────────────
    def _key_for(self, domain_id: str, key_id: str):
        desc = self._descriptors.get(domain_id)
        if desc is not None:
            for anchor in desc.trust_anchors:
                if anchor.key_id == key_id:
                    return anchor.public_key
        anchor = self._anchors.get(domain_id)
        if anchor is not None and anchor.key_id == key_id:
            return anchor.public_key
        return None

    def verify_event(self, event, at: Optional[float] = None) -> bool:
        public_key = self._key_for(event.actor_domain_id, event.key_id)
        if public_key is None:
            return False
        if self.is_revoked(event.actor_domain_id, event.key_id, at=at):
            return False
        return event.to_envelope().verify(public_key)

    def verify_checkpoint(self, checkpoint) -> bool:
        public_key = self._key_for(checkpoint.domain_id, checkpoint.key_id)
        if public_key is None:
            return False
        return checkpoint.verify(public_key)

    # ── routing ────────────────────────────────────────────
    def route_query(self, *, target_domain: str, visited_domains: list,
                    max_hops: int = MAX_ROUTE_HOPS) -> dict:
        """Resolve the next gateway for a target domain."""
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
            return {"status": "unknown", "next_hop": None,
                    "domain": target_domain}

        gateways = sorted(desc.gateways, key=lambda g: g.priority)
        if not gateways:
            return {"status": "unreachable", "next_hop": None,
                    "domain": target_domain}
        best = gateways[0]
        return {
            "status": "resolved",
            "next_hop": best.uri,
            "transport": best.transport,
            "profiles": list(best.profiles),
            "domain": target_domain,
        }

    def get(self, domain_id: str) -> Optional[DomainDescriptor]:
        return self._descriptors.get(domain_id)

    def count(self) -> int:
        return len(self._descriptors)
