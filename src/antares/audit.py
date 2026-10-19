"""Audit — causal evidence events (spec 2.1).

Enforced on `add`:
  - an event must not reference itself as a parent
  - the known causal graph must stay acyclic
  - at most MAX_PARENT_EVENTS direct parents
  - missing parents are signed into `ur` and marked unresolved, not rejected
  - every event commits to its parent cone (`cr` / `cs`), which is what makes
    "my evidence was not truncated" provable instead of merely asserted
  - evidence is bound by a Merkle root (`er`), never by a placeholder digest

This is a message-format + verification library. It does not open sockets.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .envelope import Envelope, EnvelopeError
from .merkle import merkle_root_hex, sha256
from .types import (
    ALG_ED25519,
    MAX_PARENT_EVENTS,
    MSG_EVENT,
    ErrorCode,
)

CONE_TAG = b"antares.cone.v1"
PARENT_NODE_TAG = b"antares.pnode.v1"
EVIDENCE_TAG = b"antares.evidence.v1"

BODY_KEYS = (
    "eid", "par", "an", "ad", "typ", "rid", "rv", "sb", "sa",
    "er", "en", "rc", "ob", "lc", "ur", "cr", "cs", "sl", "ts", "x",
)


def parse_digest(value: str) -> bytes:
    """Parse a ``sha256:<hex>`` digest into raw bytes."""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"not a sha256 digest: {value!r}")
    raw = bytes.fromhex(value[len("sha256:"):])
    if len(raw) != 32:
        raise ValueError("digest must be 32 bytes")
    return raw


def digest_bytes(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError("digest must be 32 bytes")
    return "sha256:" + raw.hex()


def parent_node_hash(event_id: str, cone_root: str) -> bytes:
    """Leaf hash binding one parent's identity to that parent's cone."""
    return sha256(
        PARENT_NODE_TAG + event_id.encode("utf-8") + b"|"
        + cone_root.encode("utf-8")
    )


def cone_root_of(parents) -> str:
    """Commit to a set of ``(event_id, cone_root)`` pairs.

    Sorted by event id, so declaration order never changes the root.
    """
    pairs = sorted(parents)
    h = hashlib.sha256(CONE_TAG + bytes([len(pairs) & 0xFF]))
    for event_id, root in pairs:
        h.update(parent_node_hash(event_id, root))
    return "sha256:" + h.hexdigest()


def evidence_root_of(blobs) -> str:
    """Merkle root over evidence blobs (order as supplied)."""
    return merkle_root_hex(blobs)


def single_blob_evidence_root(digest: str) -> str:
    """Root for an externally stored blob referenced only by its digest."""
    return digest_bytes(sha256(EVIDENCE_TAG + parse_digest(digest)))


@dataclass
class AuditEvent:
    event_id: str
    parent_event_ids: list = field(default_factory=list)
    actor_node_id: str = ""
    actor_domain_id: str = ""
    event_type: str = ""
    rule_id: str = ""
    rule_version: str = ""
    state_before_hash: str = ""
    state_after_hash: str = ""
    evidence_root: str = ""
    evidence_count: int = 0
    result_code: str = ""
    observed_at: str = ""
    logical_clock: int = 0
    unresolved_parents: list = field(default_factory=list)
    cone_root: str = ""
    cone_size: int = 0
    slots: dict = field(default_factory=dict)   # name -> seal commitment
    tsr_hash: str = ""                          # RFC 3161 token digest, if any
    ext: dict = field(default_factory=dict)
    key_id: str = ""
    alg: str = ALG_ED25519
    ctx: bytes = b""
    signature: str = ""

    # ── body / wire ────────────────────────────────────────
    def to_body(self) -> dict:
        return {
            "eid": self.event_id,
            "par": list(self.parent_event_ids),
            "an": self.actor_node_id,
            "ad": self.actor_domain_id,
            "typ": self.event_type,
            "rid": self.rule_id,
            "rv": self.rule_version,
            "sb": self.state_before_hash,
            "sa": self.state_after_hash,
            "er": self.evidence_root,
            "en": int(self.evidence_count),
            "rc": self.result_code,
            "ob": self.observed_at,
            "lc": int(self.logical_clock),
            "ur": list(self.unresolved_parents),
            "cr": self.cone_root,
            "cs": int(self.cone_size),
            "sl": dict(self.slots),
            "ts": self.tsr_hash,
            "x": dict(self.ext),
        }

    def to_envelope(self) -> Envelope:
        return Envelope(
            msg=MSG_EVENT,
            body=self.to_body(),
            ctx=self.ctx,
            key_id=self.key_id or self.actor_node_id,
            alg=self.alg,
            signature=self.signature,
        )

    def to_wire(self) -> dict:
        return self.to_envelope().to_wire()

    def wire_hash(self) -> str:
        return self.to_envelope().wire_hash()

    @classmethod
    def from_wire(cls, wire: dict) -> "AuditEvent":
        env = Envelope.from_wire(wire)
        if env.msg != MSG_EVENT:
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                f"expected {MSG_EVENT}, got {env.msg}")
        body = env.body
        missing = [k for k in BODY_KEYS if k not in body]
        extra = [k for k in body if k not in BODY_KEYS]
        if missing or extra:
            raise EnvelopeError(
                ErrorCode.BODY_INVALID,
                f"event body invalid (missing={missing}, extra={extra})",
            )
        for key in ("eid", "an", "ad", "typ", "rid", "rv", "sb", "sa",
                    "er", "rc", "ob", "cr", "ts"):
            if not isinstance(body[key], str):
                raise EnvelopeError(ErrorCode.BODY_INVALID,
                                    f"body[{key!r}] must be str")
        for key in ("en", "lc", "cs"):
            if not isinstance(body[key], int) or isinstance(body[key], bool):
                raise EnvelopeError(ErrorCode.BODY_INVALID,
                                    f"body[{key!r}] must be int")
        for key in ("par", "ur"):
            if not isinstance(body[key], list) or not all(
                isinstance(v, str) for v in body[key]
            ):
                raise EnvelopeError(ErrorCode.BODY_INVALID,
                                    f"body[{key!r}] must be list[str]")
        for key in ("sl", "x"):
            if not isinstance(body[key], dict):
                raise EnvelopeError(ErrorCode.BODY_INVALID,
                                    f"body[{key!r}] must be a map")
        if len(body["par"]) > MAX_PARENT_EVENTS:
            raise EnvelopeError(ErrorCode.TOO_MANY_PARENTS,
                                "parent count exceeds bound")
        if not all(isinstance(k, str) and isinstance(v, str)
                   for k, v in body["sl"].items()):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "slots must map str -> commitment")
        return cls(
            event_id=body["eid"],
            parent_event_ids=list(body["par"]),
            actor_node_id=body["an"],
            actor_domain_id=body["ad"],
            event_type=body["typ"],
            rule_id=body["rid"],
            rule_version=body["rv"],
            state_before_hash=body["sb"],
            state_after_hash=body["sa"],
            evidence_root=body["er"],
            evidence_count=body["en"],
            result_code=body["rc"],
            observed_at=body["ob"],
            logical_clock=body["lc"],
            unresolved_parents=list(body["ur"]),
            cone_root=body["cr"],
            cone_size=body["cs"],
            slots=dict(body["sl"]),
            tsr_hash=body["ts"],
            ext=dict(body["x"]),
            key_id=env.key_id,
            alg=env.alg,
            ctx=env.ctx,
            signature=env.signature,
        )


class AuditError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class AuditLog:
    """Local causal event log. Signs events on add with an Ed25519 key."""

    def __init__(self, *, signing_key=None, context_id: bytes = b"",
                 key_id: str = "", alg: str = ALG_ED25519,
                 domain_id: str = ""):
        self.context_id = bytes(context_id)
        self._signing_key = signing_key
        self.key_id = key_id
        self.alg = alg
        self.domain_id = domain_id
        self._events: dict = {}
        self._children: dict = {}
        self._ancestors: dict = {}

    # ── graph checks ───────────────────────────────────────
    def _would_cycle(self, event_id: str, parents) -> bool:
        stack = list(parents)
        seen = set()
        while stack:
            cur = stack.pop()
            if cur == event_id:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            for child in self._children.get(cur, ()):
                stack.append(child)
        return False

    # ── write ──────────────────────────────────────────────
    def add(self, event: AuditEvent, *, evidence=None) -> str:
        if len(event.parent_event_ids) > MAX_PARENT_EVENTS:
            raise AuditError(
                ErrorCode.TOO_MANY_PARENTS,
                f"parents {len(event.parent_event_ids)} > "
                f"{MAX_PARENT_EVENTS}",
            )
        if event.event_id in event.parent_event_ids:
            raise AuditError(ErrorCode.CAUSAL_CYCLE,
                             "event references itself as parent")
        if self._would_cycle(event.event_id, event.parent_event_ids):
            raise AuditError(ErrorCode.CAUSAL_CYCLE,
                             "would create causal cycle")
        if event.event_id in self._events:
            raise AuditError(ErrorCode.DUPLICATE_ENTITY,
                             f"event {event.event_id} already present")

        if evidence is not None:
            event.evidence_root = evidence_root_of(evidence)
            event.evidence_count = len(list(evidence))

        # Missing parents are signed into the body, not silently dropped.
        event.unresolved_parents = [
            p for p in event.parent_event_ids if p not in self._events
        ]

        known_parents = [
            (p, self._events[p].cone_root)
            for p in event.parent_event_ids if p in self._events
        ]
        event.cone_root = cone_root_of(known_parents)

        ancestors = set()
        for p in event.parent_event_ids:
            if p in self._events:
                ancestors.add(p)
                ancestors |= self._ancestors.get(p, set())
        event.cone_size = len(ancestors)

        if self._signing_key is None:
            raise AuditError(ErrorCode.MISSING_SIGNING_KEY,
                             "AuditLog requires a signing_key")
        if not event.ctx:
            event.ctx = self.context_id
        if not event.key_id:
            event.key_id = (self.key_id or event.actor_node_id
                            or event.actor_domain_id or "unknown")
        event.alg = self.alg
        event.signature = self._sign(event)

        self._events[event.event_id] = event
        self._ancestors[event.event_id] = ancestors
        for p in event.parent_event_ids:
            self._children.setdefault(p, set()).add(event.event_id)
        return event.signature

    # ── canonical form / signature ─────────────────────────
    def canonical_bytes(self, event: AuditEvent) -> bytes:
        """Deterministic bytes covered by the event signature."""
        return event.to_envelope().signed_bytes()

    def _sign(self, event: AuditEvent) -> str:
        return event.to_envelope().sign(self._signing_key).signature

    def verify_signature(self, event: AuditEvent, public_key) -> bool:
        """Verify with the actor's public key. No shared secret needed."""
        try:
            return event.to_envelope().verify(
                public_key, expect_msg=MSG_EVENT
            )
        except Exception:
            return False

    # ── read ───────────────────────────────────────────────
    def get(self, event_id: str) -> Optional[AuditEvent]:
        return self._events.get(event_id)

    def count(self) -> int:
        return len(self._events)

    def list_events(self) -> list:
        return list(self._events.values())

    def wire_list(self) -> list:
        return [e.to_wire() for e in self._events.values()]

    def ancestors_of(self, event_id: str) -> set:
        return set(self._ancestors.get(event_id, set()))


# ── cone verification (works on a disclosed subgraph) ──────
def verify_cone(wires) -> dict:
    """Recompute every cone root over the events actually supplied.

    Returns a report with:
      ok                     no root mismatch and no undeclared missing parent
      complete               every parent is present (the cone is closed)
      cone_root_mismatch     recomputed root/size differs from the claim
      unverifiable           declared-missing parents, so the root cannot be
                             recomputed — evidence is incomplete, not false
      undeclared_missing     parent absent but not declared in `ur`
      false_unresolved       declared unresolved although present in the set
    """
    events = {}
    for wire in wires:
        event = AuditEvent.from_wire(wire)
        prior = events.get(event.event_id)
        if prior is not None and prior.wire_hash() != event.wire_hash():
            raise AuditError(
                ErrorCode.DUPLICATE_ENTITY,
                f"two different events share id {event.event_id}",
            )
        events[event.event_id] = event

    computed = {}
    ancestor_sets = {}
    mismatch = []
    unverifiable = []
    undeclared = {}
    declared = {}
    false_unresolved = []
    visiting = set()

    def compute(event_id: str):
        if event_id in computed:
            return computed[event_id]
        if event_id in visiting:
            raise AuditError(ErrorCode.CAUSAL_CYCLE,
                             f"cycle through {event_id}")
        visiting.add(event_id)
        event = events[event_id]
        parents = []
        ancestors = set()
        for parent_id in event.parent_event_ids:
            if parent_id in events:
                parent_root, _ = compute(parent_id)
                parents.append((parent_id, parent_root))
                ancestors.add(parent_id)
                ancestors |= ancestor_sets[parent_id]
            elif parent_id in event.unresolved_parents:
                declared.setdefault(event_id, []).append(parent_id)
            else:
                undeclared.setdefault(event_id, []).append(parent_id)

        root = cone_root_of(parents)
        size = len(ancestors)
        ancestor_sets[event_id] = ancestors
        computed[event_id] = (root, size)

        if any(p in events for p in event.unresolved_parents):
            false_unresolved.append(event_id)
        if event_id in declared:
            unverifiable.append(event_id)
        elif root != event.cone_root or size != event.cone_size:
            mismatch.append(event_id)
        visiting.discard(event_id)
        return computed[event_id]

    for event_id in events:
        compute(event_id)

    return {
        "ok": not mismatch and not undeclared,
        "complete": not declared and not undeclared,
        "events": len(events),
        "cone_root_mismatch": sorted(mismatch),
        "unverifiable": sorted(unverifiable),
        "undeclared_missing_parents": {
            k: sorted(v) for k, v in undeclared.items()
        },
        "declared_missing_parents": {
            k: sorted(v) for k, v in declared.items()
        },
        "false_unresolved": sorted(false_unresolved),
    }
