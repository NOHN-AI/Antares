"""Audit — causal event log.
Enforces:
  - an event must not reference itself as a parent
  - the known causal graph must stay acyclic
  - at most MAX_PARENT_EVENTS direct parents
  - missing parents are marked unresolved, NOT rejected
  - signatures cover canonical CBOR bytes (version, event header, payload hash)

This is a message-format + verification library. It does not open sockets.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .cbor_utils import encode_deterministic
from .signing import sign as ed25519_sign, verify as ed25519_verify
from .types import (
    SPEC_VERSION,
    ErrorCode,
    MAX_PARENT_EVENTS,
)


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
    evidence_hash: str = ""
    result_code: str = ""
    observed_at: str = ""
    logical_clock: int = 0
    unresolved_parents: list = field(default_factory=list)
    signature: str = ""


class AuditError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class AuditLog:
    """Local causal event log. Signs events on add with an Ed25519 key."""

    def __init__(self, *, signing_key: Optional[bytes] = None,
                 context_id: bytes = b""):
        self.context_id = context_id  # session/conversation/task identifier
        self._signing_key = signing_key  # raw 32-byte Ed25519 private key
        self._events: dict[str, AuditEvent] = {}
        self._children: dict[str, set] = {}  # parent -> children

    # ── graph checks ───────────────────────────────────────
    def _would_cycle(self, event_id: str, parents: list) -> bool:
        """DFS from parents; if we reach event_id, a cycle would form."""
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
    def add(self, event: AuditEvent) -> str:
        if len(event.parent_event_ids) > MAX_PARENT_EVENTS:
            raise AuditError(
                ErrorCode.TOO_MANY_PARENTS,
                f"parents {len(event.parent_event_ids)} > {MAX_PARENT_EVENTS}",
            )
        if event.event_id in event.parent_event_ids:
            raise AuditError(ErrorCode.CAUSAL_CYCLE,
                             "event references itself as parent")
        if self._would_cycle(event.event_id, event.parent_event_ids):
            raise AuditError(ErrorCode.CAUSAL_CYCLE,
                             "would create causal cycle")

        # Missing parents are recorded, not rejected.
        event.unresolved_parents = [
            p for p in event.parent_event_ids if p not in self._events
        ]

        if self._signing_key is None:
            raise AuditError(
                ErrorCode.MISSING_SIGNING_KEY,
                "AuditLog requires an Ed25519 signing_key",
            )
        event.signature = self._sign(event)

        self._events[event.event_id] = event
        for p in event.parent_event_ids:
            self._children.setdefault(p, set()).add(event.event_id)
        return event.signature

    # ── canonical form / signature ─────────────────────────
    def canonical_bytes(self, event: AuditEvent) -> bytes:
        """Deterministic bytes covered by the event signature."""
        header = {
            "eid": event.event_id,
            "par": event.parent_event_ids,
            "act": event.actor_node_id,
            "dom": event.actor_domain_id,
            "typ": event.event_type,
            "rid": event.rule_id,
            "rv": event.rule_version,
            "sb": event.state_before_hash,
            "sa": event.state_after_hash,
            "ev": event.evidence_hash,
            "rc": event.result_code,
            "ob": event.observed_at,
            "lc": event.logical_clock,
        }
        payload_digest = hashlib.sha256(
            f"{event.event_type}:{event.result_code}".encode()
        ).hexdigest()
        return encode_deterministic({
            "ver": SPEC_VERSION,
            "ctx": self.context_id,
            "hdr": header,
            "ph": payload_digest,
        })

    def _sign(self, event: AuditEvent) -> str:
        return ed25519_sign(
            self._signing_key, self.canonical_bytes(event)
        ).hex()

    def verify_signature(self, event: AuditEvent,
                         public_key: bytes) -> bool:
        """Verify with the actor's public key. No shared secret needed."""
        try:
            sig = bytes.fromhex(event.signature)
        except (ValueError, TypeError):
            return False
        return ed25519_verify(
            public_key, self.canonical_bytes(event), sig
        )

    # ── read ───────────────────────────────────────────────
    def get(self, event_id: str) -> Optional[AuditEvent]:
        return self._events.get(event_id)

    def count(self) -> int:
        return len(self._events)

    def list_events(self) -> list:
        return list(self._events.values())
