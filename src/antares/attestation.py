"""Attestation — the audit itself is auditable (spec §10).

An attestation is a signed verdict about a *specific causal cone*, produced
by a named auditor running a named operator set. Because the verdict is
itself a message, it can be checkpointed and audited in turn: trust does not
have to be bootstrapped from an authority nobody can inspect.

The operator-set hash is the answer to "which pipeline produced this
verdict"; two runs can only be compared when they agree on it.
"""
from dataclasses import dataclass, field

from .audit import AuditEvent
from .cbor_utils import encode_deterministic
from .envelope import Envelope, EnvelopeError
from .merkle import digest_hex, sha256
from .types import ALG_ED25519, ErrorCode, MSG_ATTESTATION

ATTESTATION_KEYS = ("aid", "kind", "tar", "tsz", "aud", "om",
                    "osh", "vd", "fr", "sup", "at")
ATTESTATION_KINDS = ("audit", "adjudicate")
VERDICTS = ("pass", "block", "undecided")

OPERATOR_SET_TAG = b"antares.operatorset.v1"


def normalize_manifest(manifest) -> list:
    """`[{n, l, i}]` — name, permission layer, position in the pipeline."""
    normalized = []
    for index, entry in enumerate(manifest or []):
        if not isinstance(entry, dict):
            raise ValueError("operator entry must be a map")
        normalized.append({
            "n": str(entry.get("n", entry.get("name", ""))),
            "l": str(entry.get("l", entry.get("layer", ""))),
            "i": int(entry.get("i", entry.get("index", index))),
        })
    return normalized


def operator_set_hash(manifest) -> str:
    """Fingerprint of the operator set: names + layers + order."""
    normalized = normalize_manifest(manifest)
    return digest_hex(
        sha256(OPERATOR_SET_TAG + encode_deterministic(normalized))
    )


class AttestationError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass
class Attestation:
    attestation_id: str
    target_cone_root: str
    target_size: int = 0
    kind: str = "audit"
    auditor_domain: str = ""
    operator_manifest: list = field(default_factory=list)
    verdict: str = "undecided"
    findings_root: str = ""
    supersedes: str = ""
    issued_at: str = ""
    key_id: str = ""
    alg: str = ALG_ED25519
    ctx: bytes = b""
    signature: str = ""

    @property
    def operator_set_hash(self) -> str:
        return operator_set_hash(self.operator_manifest)

    def to_body(self) -> dict:
        return {
            "aid": self.attestation_id,
            "kind": self.kind,
            "tar": self.target_cone_root,
            "tsz": int(self.target_size),
            "aud": self.auditor_domain,
            "om": normalize_manifest(self.operator_manifest),
            "osh": self.operator_set_hash,
            "vd": self.verdict,
            "fr": self.findings_root,
            "sup": self.supersedes,
            "at": self.issued_at,
        }

    def to_envelope(self) -> Envelope:
        return Envelope(
            msg=MSG_ATTESTATION,
            body=self.to_body(),
            ctx=self.ctx,
            key_id=self.key_id,
            alg=self.alg,
            signature=self.signature,
        )

    def to_wire(self) -> dict:
        return self.to_envelope().to_wire()

    def sign(self, private_key, key_id: str = "") -> "Attestation":
        if self.kind not in ATTESTATION_KINDS:
            raise AttestationError(ErrorCode.BODY_INVALID,
                                   f"unknown kind {self.kind!r}")
        if self.verdict not in VERDICTS:
            raise AttestationError(ErrorCode.BODY_INVALID,
                                   f"unknown verdict {self.verdict!r}")
        env = self.to_envelope()
        env.sign(private_key, key_id=key_id)
        self.key_id, self.alg, self.signature = env.key_id, env.alg, env.signature
        return self

    def verify(self, public_key) -> bool:
        try:
            env = Envelope.from_wire(self.to_wire())
        except EnvelopeError:
            return False
        if env.body.get("osh") != self.operator_set_hash:
            return False
        return env.verify(public_key, expect_msg=MSG_ATTESTATION)

    def to_event(self, *, parent_event_ids=None, actor_node_id: str = "",
                 observed_at: str = "", logical_clock: int = 0) -> AuditEvent:
        """Turn the verdict into an audit event, so it can be audited too."""
        return AuditEvent(
            event_id=self.attestation_id,
            parent_event_ids=list(parent_event_ids or []),
            actor_node_id=actor_node_id or self.auditor_domain,
            actor_domain_id=self.auditor_domain,
            event_type=f"audit.{self.kind}",
            rule_id="antares.attestation",
            rule_version=self.operator_set_hash,
            evidence_root=self.target_cone_root,
            evidence_count=1,
            result_code=self.verdict,
            observed_at=observed_at or self.issued_at,
            logical_clock=logical_clock,
            ext={
                "osh": self.operator_set_hash,
                "tar": self.target_cone_root,
                "tsz": int(self.target_size),
                "fr": self.findings_root,
            },
        )

    @classmethod
    def from_wire(cls, wire: dict) -> "Attestation":
        env = Envelope.from_wire(wire)
        if env.msg != MSG_ATTESTATION:
            raise AttestationError(ErrorCode.BODY_INVALID,
                                   f"expected {MSG_ATTESTATION}")
        body = env.body
        if set(body) != set(ATTESTATION_KEYS):
            raise AttestationError(ErrorCode.BODY_INVALID,
                                   "attestation body key set invalid")
        if body["kind"] not in ATTESTATION_KINDS:
            raise AttestationError(ErrorCode.BODY_INVALID,
                                   f"unknown kind {body['kind']!r}")
        if body["vd"] not in VERDICTS:
            raise AttestationError(ErrorCode.BODY_INVALID,
                                   f"unknown verdict {body['vd']!r}")
        manifest = normalize_manifest(body["om"])
        if body["osh"] != digest_hex(
            sha256(OPERATOR_SET_TAG + encode_deterministic(manifest))
        ):
            raise AttestationError(
                ErrorCode.BODY_INVALID,
                "operator-set hash does not match the manifest",
            )
        return cls(
            attestation_id=body["aid"],
            target_cone_root=body["tar"],
            target_size=body["tsz"],
            kind=body["kind"],
            auditor_domain=body["aud"],
            operator_manifest=manifest,
            verdict=body["vd"],
            findings_root=body["fr"],
            supersedes=body["sup"],
            issued_at=body["at"],
            key_id=env.key_id,
            alg=env.alg,
            ctx=env.ctx,
            signature=env.signature,
        )
