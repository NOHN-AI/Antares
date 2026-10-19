"""Signed envelope — the single signature surface of Antares 2.1.

Every message family (audit event, checkpoint, warrant, attestation,
descriptor) travels inside the same envelope. The signature always covers
the canonical CBOR of:

    { "v": "2.1", "m": <message family>, "c": <context bytes>,
      "k": <key_id>, "a": <algorithm>, "b": <body> }

Why each field is inside the signature:
  v  version pinning, blocks downgrade to the 2.0 envelope
  m  domain separation, blocks cross-family signature confusion
  c  context binding, so a message verifies on its own without the log
  k  key identity, so "who signed" is part of the evidence
  a  algorithm identity, so a verifier can never be downgraded silently
  b  the message body

Unknown wire keys are rejected: anything outside this map would otherwise be
unsigned data travelling next to signed data.
"""
import hashlib
from dataclasses import dataclass, field

from .cbor_utils import decode, encode_deterministic
from .signing import (
    SigningError,
    decode_signature,
    encode_signature,
    sign_bytes,
    verify_bytes,
)
from .types import ALG_ED25519, SPEC_VERSION, ErrorCode

WIRE_KEYS = frozenset({"v", "m", "c", "k", "a", "b", "s"})
SIGNED_KEYS = ("v", "m", "c", "k", "a", "b")


class EnvelopeError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass
class Envelope:
    msg: str
    body: dict = field(default_factory=dict)
    ctx: bytes = b""
    key_id: str = ""
    alg: str = ALG_ED25519
    signature: str = ""

    # ── signed bytes ───────────────────────────────────────
    def signed_map(self) -> dict:
        return {
            "v": SPEC_VERSION,
            "m": self.msg,
            "c": bytes(self.ctx),
            "k": self.key_id,
            "a": self.alg,
            "b": self.body,
        }

    def signed_bytes(self) -> bytes:
        return encode_deterministic(self.signed_map())

    def to_wire(self) -> dict:
        wire = self.signed_map()
        wire["s"] = self.signature
        return wire

    def to_wire_bytes(self) -> bytes:
        return encode_deterministic(self.to_wire())

    def wire_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self.to_wire_bytes()).hexdigest()

    # ── signing ────────────────────────────────────────────
    def sign(self, private_key, key_id: str = "") -> "Envelope":
        if key_id:
            self.key_id = key_id
        components = sign_bytes(self.alg, private_key, self.signed_bytes())
        self.signature = encode_signature(components)
        return self

    def verify(self, public_key, *, expect_msg: str = "",
               expect_ctx: bytes = b"") -> bool:
        if expect_msg and self.msg != expect_msg:
            return False
        if expect_ctx and bytes(self.ctx) != bytes(expect_ctx):
            return False
        try:
            components = decode_signature(self.signature)
        except SigningError:
            return False
        return verify_bytes(self.alg, public_key, self.signed_bytes(),
                            components)

    # ── wire ───────────────────────────────────────────────
    def to_wire_validated(self) -> dict:
        """Wire map after re-checking that nothing unsigned slipped in."""
        wire = self.to_wire()
        if set(wire) != set(WIRE_KEYS):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "wire key set does not match the envelope")
        return wire

    @classmethod
    def from_wire(cls, wire: dict) -> "Envelope":
        if not isinstance(wire, dict):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "envelope must be a CBOR map")
        if set(wire) != set(WIRE_KEYS):
            extra = set(wire) - set(WIRE_KEYS)
            missing = set(WIRE_KEYS) - set(wire)
            raise EnvelopeError(
                ErrorCode.BODY_INVALID,
                f"envelope keys invalid (extra={sorted(extra)}, "
                f"missing={sorted(missing)})",
            )
        if wire["v"] != SPEC_VERSION:
            raise EnvelopeError(
                ErrorCode.BODY_INVALID,
                f"unsupported envelope version {wire['v']!r}",
            )
        if not isinstance(wire["m"], str) or not isinstance(wire["b"], dict):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "msg must be str and body must be a map")
        if not isinstance(wire["c"], bytes):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "ctx must be bytes")
        if not isinstance(wire["k"], str) or not isinstance(wire["a"], str):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "key_id and alg must be strings")
        if not isinstance(wire["s"], str):
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                "signature must be a hex string")
        return cls(
            msg=wire["m"],
            body=wire["b"],
            ctx=wire["c"],
            key_id=wire["k"],
            alg=wire["a"],
            signature=wire["s"],
        )

    @classmethod
    def from_wire_bytes(cls, data: bytes) -> "Envelope":
        try:
            return cls.from_wire(decode(data))
        except EnvelopeError:
            raise
        except Exception as exc:
            raise EnvelopeError(ErrorCode.BODY_INVALID,
                                f"cannot decode envelope: {exc}")


def verify_wire(wire: dict, public_key, *, expect_msg: str = "") -> bool:
    """Verify a wire map without constructing a domain object."""
    try:
        return Envelope.from_wire(wire).verify(public_key,
                                               expect_msg=expect_msg)
    except EnvelopeError:
        return False
