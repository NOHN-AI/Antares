"""Checkpoints, cross-anchoring, and split-view detection (spec §7).

A checkpoint is a signed commitment to a set of events:

    { "dom": domain, "seq": n, "size": m, "root": <merkle>, "prev": <hash>,
      "at": <rfc3339>, "anch": [<cross-anchor wires>] }

Two checkpoints from the same domain with the same `seq` but different
`root` are proof of equivocation (a split view), not a normal race.
"""
from dataclasses import dataclass, field

from .audit import AuditEvent
from .cbor_utils import encode_deterministic
from .envelope import Envelope, EnvelopeError
from .merkle import merkle_root_sorted, digest_hex
from .types import (
    ALG_ED25519,
    ErrorCode,
    MSG_ANCHOR,
    MSG_CHECKPOINT,
)

CHECKPOINT_KEYS = ("dom", "seq", "size", "root", "prev", "at", "anch")
ANCHOR_KEYS = ("dom", "seq", "root", "by")


class CheckpointError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _wire_of(item) -> dict:
    return item.to_wire() if isinstance(item, AuditEvent) else item


def event_set_root(items) -> str:
    """Merkle root over a set of event wires (order-independent)."""
    leaves = [encode_deterministic(_wire_of(i)) for i in items]
    return digest_hex(merkle_root_sorted(leaves))


@dataclass
class Checkpoint:
    domain_id: str
    seq: int
    size: int
    root: str
    prev: str = ""
    anchored_at: str = ""
    anchors: list = field(default_factory=list)
    key_id: str = ""
    alg: str = ALG_ED25519
    ctx: bytes = b""
    signature: str = ""

    def to_body(self) -> dict:
        return {
            "dom": self.domain_id,
            "seq": int(self.seq),
            "size": int(self.size),
            "root": self.root,
            "prev": self.prev,
            "at": self.anchored_at,
            "anch": list(self.anchors),
        }

    def to_envelope(self) -> Envelope:
        return Envelope(
            msg=MSG_CHECKPOINT,
            body=self.to_body(),
            ctx=self.ctx or self.domain_id.encode("utf-8"),
            key_id=self.key_id,
            alg=self.alg,
            signature=self.signature,
        )

    def to_wire(self) -> dict:
        return self.to_envelope().to_wire()

    def wire_hash(self) -> str:
        return self.to_envelope().wire_hash()

    def sign(self, private_key, key_id: str = "") -> "Checkpoint":
        env = self.to_envelope()
        env.sign(private_key, key_id=key_id)
        self.key_id, self.alg, self.signature = env.key_id, env.alg, env.signature
        if not self.ctx:
            self.ctx = env.ctx
        return self

    def verify(self, public_key) -> bool:
        return self.to_envelope().verify(
            public_key, expect_msg=MSG_CHECKPOINT
        )

    @classmethod
    def from_wire(cls, wire: dict) -> "Checkpoint":
        env = Envelope.from_wire(wire)
        if env.msg != MSG_CHECKPOINT:
            raise CheckpointError(ErrorCode.BODY_INVALID,
                                  f"expected {MSG_CHECKPOINT}")
        body = env.body
        if set(body) != set(CHECKPOINT_KEYS):
            raise CheckpointError(ErrorCode.BODY_INVALID,
                                  "checkpoint body key set invalid")
        if not isinstance(body["anch"], list):
            raise CheckpointError(ErrorCode.BODY_INVALID,
                                  "anch must be a list")
        return cls(
            domain_id=body["dom"],
            seq=body["seq"],
            size=body["size"],
            root=body["root"],
            prev=body["prev"],
            anchored_at=body["at"],
            anchors=list(body["anch"]),
            key_id=env.key_id,
            alg=env.alg,
            ctx=env.ctx,
            signature=env.signature,
        )


def build_checkpoint(*, domain_id: str, events, seq: int,
                     private_key=None, key_id: str = "",
                     alg: str = ALG_ED25519, prev: str = "",
                     anchored_at: str = "") -> Checkpoint:
    items = [_wire_of(e) for e in events]
    unique = {}
    for item in items:
        unique[encode_deterministic(item)] = item
    leaves = list(unique)
    cp = Checkpoint(
        domain_id=domain_id,
        seq=seq,
        size=len(leaves),
        root=digest_hex(merkle_root_sorted(leaves)),
        prev=prev,
        anchored_at=anchored_at,
        alg=alg,
        key_id=key_id,
        ctx=domain_id.encode("utf-8"),
    )
    if private_key is not None:
        cp.sign(private_key, key_id=key_id)
    return cp


def sign_anchor(target: Checkpoint, *, by_domain: str, private_key,
                key_id: str = "", alg: str = ALG_ED25519) -> dict:
    """Cross-sign a checkpoint: `I, by_domain, saw this root at this seq`."""
    env = Envelope(
        msg=MSG_ANCHOR,
        body={
            "dom": target.domain_id,
            "seq": int(target.seq),
            "root": target.root,
            "by": by_domain,
        },
        ctx=bytes(target.root, "utf-8"),
        key_id=key_id,
        alg=alg,
    )
    env.sign(private_key, key_id=key_id)
    return env.to_wire()


def verify_anchor(anchor_wire: dict, public_key, *,
                  target: Checkpoint = None) -> bool:
    try:
        env = Envelope.from_wire(anchor_wire)
    except EnvelopeError:
        return False
    if env.msg != MSG_ANCHOR or set(env.body) != set(ANCHOR_KEYS):
        return False
    if not env.verify(public_key, expect_msg=MSG_ANCHOR):
        return False
    if target is not None:
        return (env.body["dom"] == target.domain_id
                and env.body["seq"] == target.seq
                and env.body["root"] == target.root)
    return True


def detect_equivocation(a: Checkpoint, b: Checkpoint) -> bool:
    """True when two checkpoints prove a split view."""
    if a.domain_id != b.domain_id or a.seq != b.seq:
        return False
    return a.root != b.root or a.size != b.size


class CheckpointStore:
    """Ordered checkpoint chain with split-view detection."""

    def __init__(self):
        self._by_domain: dict = {}

    def add(self, cp: Checkpoint) -> None:
        chain = self._by_domain.setdefault(cp.domain_id, [])
        if not chain:
            self._by_domain[cp.domain_id] = [cp]
            return
        last = chain[-1]
        if cp.seq == last.seq:
            if detect_equivocation(last, cp):
                raise CheckpointError(
                    ErrorCode.SPLIT_VIEW,
                    f"equivocation at {cp.domain_id} seq {cp.seq}",
                )
            return
        if cp.seq < last.seq:
            raise CheckpointError(
                ErrorCode.CHECKPOINT_SEQ_STALE,
                f"seq {cp.seq} <= {last.seq}",
            )
        if cp.prev and cp.prev != last.wire_hash():
            raise CheckpointError(
                ErrorCode.CHECKPOINT_SEQ_STALE,
                "prev does not link to the previous checkpoint",
            )
        chain.append(cp)

    def last(self, domain_id: str):
        chain = self._by_domain.get(domain_id, [])
        return chain[-1] if chain else None

    def head_hash(self, domain_id: str) -> str:
        last = self.last(domain_id)
        return last.wire_hash() if last else ""

    def chain(self, domain_id: str) -> list:
        return list(self._by_domain.get(domain_id, []))

    def domains(self) -> list:
        return sorted(self._by_domain)
