"""Antares — audit and federation layer for AI agents (spec 2.1).

Capabilities:
  - Audit: signed causal events with cone commitments and completeness proofs
  - Evidence: Merkle-bound evidence, salted commitments, selective disclosure
  - Rebuttable claims: warrants, counter-evidence, adjudication
  - Attestation: the audit itself is auditable
  - Federation: signed descriptors, rotation pre-commitment, revocation
  - Bundle: one offline-verifiable `.ant` file

Transport is out of scope: carry Antares messages over HTTP/3, A2A, MCP,
or any authenticated channel.
"""
from .types import (
    SPEC_VERSION,
    ErrorCode,
    MAX_PARENT_EVENTS,
    MAX_ROUTE_HOPS,
    MAX_CONE_ROOTS,
    MAX_SLOTS,
    ALG_ED25519,
    ALG_ED25519_MLDSA65,
    MSG_EVENT,
    MSG_CHECKPOINT,
    MSG_ANCHOR,
    MSG_WARRANT,
    MSG_COUNTER_EVIDENCE,
    MSG_ATTESTATION,
    MSG_DESCRIPTOR,
)
from .cbor_utils import (
    encode_deterministic,
    decode,
    decode_any,
    is_canonical,
)
from .signing import (
    generate_keypair,
    sign,
    verify,
    sign_bytes,
    verify_bytes,
    encode_signature,
    decode_signature,
    key_id_for,
    public_key_wire,
    public_key_from_wire,
    TrustAnchorRegistry,
    SigningError,
)
from .envelope import Envelope, EnvelopeError, verify_wire
from .merkle import (
    merkle_root,
    merkle_root_hex,
    merkle_root_sorted,
    merkle_root_sorted_hex,
    inclusion_proof,
    verify_inclusion,
)
from .audit import (
    AuditLog,
    AuditEvent,
    AuditError,
    verify_cone,
    cone_root_of,
    evidence_root_of,
)
from .checkpoint import (
    Checkpoint,
    CheckpointStore,
    CheckpointError,
    build_checkpoint,
    sign_anchor,
    verify_anchor,
    detect_equivocation,
)
from .warrant import (
    Warrant,
    CounterEvidence,
    WarrantLedger,
    WarrantError,
)
from .attestation import (
    Attestation,
    AttestationError,
    operator_set_hash,
)
from .disclosure import (
    EvidenceSet,
    DisclosureError,
    commit,
    seal,
    reveal,
    seal_map,
    reveal_map,
)
from .bundle import (
    build_bundle,
    verify_bundle,
    write_bundle,
    read_bundle,
    BundleError,
)
from .federation import (
    FederationRegistry,
    DomainDescriptor,
    Gateway,
    TrustAnchor,
    RevocationEntry,
    FederationError,
    key_fingerprint,
    sign_descriptor,
    descriptor_canonical_bytes,
    sign_gateway_pop,
    verify_gateway_pop,
    gateway_pop_bytes,
)
from .business import BusinessHandler, SimpleKVStore, state_hash

__version__ = "2.1.0"

__all__ = [
    "SPEC_VERSION", "ErrorCode",
    "MAX_PARENT_EVENTS", "MAX_ROUTE_HOPS", "MAX_CONE_ROOTS", "MAX_SLOTS",
    "ALG_ED25519", "ALG_ED25519_MLDSA65",
    "MSG_EVENT", "MSG_CHECKPOINT", "MSG_ANCHOR", "MSG_WARRANT",
    "MSG_COUNTER_EVIDENCE", "MSG_ATTESTATION", "MSG_DESCRIPTOR",
    "encode_deterministic", "decode", "decode_any", "is_canonical",
    "generate_keypair", "sign", "verify", "sign_bytes", "verify_bytes",
    "encode_signature", "decode_signature", "key_id_for",
    "public_key_wire", "public_key_from_wire", "TrustAnchorRegistry",
    "SigningError",
    "Envelope", "EnvelopeError", "verify_wire",
    "merkle_root", "merkle_root_hex", "merkle_root_sorted",
    "merkle_root_sorted_hex", "inclusion_proof", "verify_inclusion",
    "AuditLog", "AuditEvent", "AuditError", "verify_cone", "cone_root_of",
    "evidence_root_of",
    "Checkpoint", "CheckpointStore", "CheckpointError", "build_checkpoint",
    "sign_anchor", "verify_anchor", "detect_equivocation",
    "Warrant", "CounterEvidence", "WarrantLedger", "WarrantError",
    "Attestation", "AttestationError", "operator_set_hash",
    "EvidenceSet", "DisclosureError", "commit", "seal", "reveal",
    "seal_map", "reveal_map",
    "build_bundle", "verify_bundle", "write_bundle", "read_bundle",
    "BundleError",
    "FederationRegistry", "DomainDescriptor", "Gateway", "TrustAnchor",
    "RevocationEntry", "FederationError", "key_fingerprint",
    "sign_descriptor", "descriptor_canonical_bytes",
    "sign_gateway_pop", "verify_gateway_pop", "gateway_pop_bytes",
    "BusinessHandler", "SimpleKVStore", "state_hash",
]
