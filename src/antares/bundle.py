"""Self-contained evidence bundle — the ``.ant`` file (spec §11).

One file that a regulator, a court, or an opposing party can verify offline:
events, checkpoints, attestations, evidence chunks with salts, selective
disclosure proofs, and external timestamp tokens.

File layout::

    b"ANTARES1\\n" + canonical CBOR(map)

The map carries a `manifest` with a hash over everything else. Verification
is therefore two-phase: first prove the container was not edited, then prove
the content.
"""
import hashlib
import os
from typing import Iterable

from .audit import AuditEvent, verify_cone
from .attestation import Attestation, AttestationError
from .cbor_utils import decode_any, encode_deterministic
from .checkpoint import Checkpoint, CheckpointError, detect_equivocation
from .disclosure import EvidenceSet
from .envelope import EnvelopeError
from .merkle import digest_hex, merkle_root_sorted
from .types import ErrorCode, MSG_ATTESTATION, MSG_CHECKPOINT, MSG_EVENT

MAGIC = b"ANTARES1\n"
BUNDLE_VERSION = "2.1"
BUNDLE_KEYS = (
    "v", "created_at", "events", "checkpoints", "attestations",
    "evidence", "disclosures", "timestamps", "manifest",
)
BUNDLE_TAG = b"antares.bundle.v1"


class BundleError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _wire(item) -> dict:
    return item.to_wire() if hasattr(item, "to_wire") else item


def _dedupe(items: Iterable) -> list:
    uniq = {}
    for item in items:
        wire = _wire(item)
        uniq[encode_deterministic(wire)] = wire
    return [uniq[k] for k in sorted(uniq)]


def build_bundle(*, events=(), checkpoints=(), attestations=(),
                 evidence: EvidenceSet = None, disclosures=(),
                 timestamps=(), created_at: str = "") -> bytes:
    """Assemble a bundle and return the file bytes."""
    event_wires = _dedupe(events)
    cp_wires = _dedupe(checkpoints)
    att_wires = _dedupe(attestations)

    evidence_items = []
    evidence_root = ""
    if evidence is not None and len(evidence):
        evidence_items = [
            {"cmt": cmt, "salt": salt, "data": data}
            for salt, data, cmt in evidence.items()
        ]
        evidence_root = evidence.root()

    leaves = [encode_deterministic(w) for w in event_wires]
    core = {
        "v": BUNDLE_VERSION,
        "created_at": created_at,
        "events": event_wires,
        "checkpoints": cp_wires,
        "attestations": att_wires,
        "evidence": evidence_items,
        "disclosures": list(disclosures),
        "timestamps": list(timestamps),
    }
    manifest = {
        "counts": {
            "events": len(event_wires),
            "checkpoints": len(cp_wires),
            "attestations": len(att_wires),
            "evidence": len(evidence_items),
            "disclosures": len(list(disclosures)),
            "timestamps": len(list(timestamps)),
        },
        "event_root": digest_hex(merkle_root_sorted(leaves)) if leaves else "",
        "evidence_root": evidence_root,
        "bundle_hash": digest_hex(
            hashlib.sha256(BUNDLE_TAG + encode_deterministic(core)).digest()
        ),
    }
    payload = dict(core)
    payload["manifest"] = manifest
    return MAGIC + encode_deterministic(payload)


def write_bundle(path: str, data: bytes) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def read_bundle(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _resolve(resolver, key_id: str):
    if resolver is None:
        return None
    if isinstance(resolver, dict):
        return resolver.get(key_id)
    try:
        return resolver(key_id)
    except Exception:
        return None


def verify_bundle(data: bytes, resolver=None, *,
                  require_keys: bool = True,
                  timestamp_verifier=None) -> dict:
    """Verify a bundle offline.

    `resolver` maps key_id -> public key (dict or callable). Without it,
    signatures are reported as unverified rather than silently trusted.
    """
    errors = []
    warnings = []
    report = {
        "ok": False,
        "events": 0,
        "checkpoints": 0,
        "attestations": 0,
        "errors": errors,
        "warnings": warnings,
    }

    if not isinstance(data, (bytes, bytearray)) or not bytes(data).startswith(MAGIC):
        errors.append({"code": int(ErrorCode.BODY_INVALID),
                       "detail": "missing ANTARES1 magic"})
        return report

    try:
        payload = decode_any(bytes(data)[len(MAGIC):])
    except Exception as exc:
        errors.append({"code": int(ErrorCode.BODY_INVALID),
                       "detail": f"cannot decode bundle: {exc}"})
        return report

    if not isinstance(payload, dict) or set(payload) != set(BUNDLE_KEYS):
        errors.append({"code": int(ErrorCode.BODY_INVALID),
                       "detail": "bundle key set invalid"})
        return report

    manifest = payload["manifest"]
    core = {k: v for k, v in payload.items() if k != "manifest"}
    recomputed = digest_hex(
        hashlib.sha256(BUNDLE_TAG + encode_deterministic(core)).digest()
    )
    if recomputed != manifest.get("bundle_hash"):
        errors.append({"code": int(ErrorCode.BUNDLE_MANIFEST_MISMATCH),
                       "detail": "manifest hash does not cover the content"})

    # ── events ─────────────────────────────────────────────
    event_wires = payload["events"]
    events = []
    for wire in event_wires:
        try:
            events.append(AuditEvent.from_wire(wire))
        except (EnvelopeError, Exception) as exc:
            errors.append({"code": int(ErrorCode.BODY_INVALID),
                           "detail": f"bad event: {exc}"})
    report["events"] = len(events)

    key_unverified = 0
    for event in events:
        public_key = _resolve(resolver, event.key_id)
        if public_key is None:
            key_unverified += 1
            continue
        if not event.to_envelope().verify(public_key, expect_msg=MSG_EVENT):
            errors.append({"code": int(ErrorCode.POLICY_REJECTED),
                           "detail": f"signature invalid: {event.event_id}"})

    if key_unverified:
        message = f"{key_unverified} event(s) could not be checked: unknown key"
        if require_keys:
            errors.append({"code": int(ErrorCode.REVOKED_KEY),
                           "detail": message})
        else:
            warnings.append({"code": int(ErrorCode.TIMESTAMP_UNVERIFIED),
                             "detail": message})

    if events:
        cone = verify_cone([e.to_wire() for e in events])
        report["cone"] = cone
        if not cone["ok"]:
            errors.append({"code": int(ErrorCode.CONE_ROOT_MISMATCH),
                           "detail": "causal cone commitment mismatch"})
        if not cone["complete"]:
            warnings.append({"code": int(ErrorCode.CONE_INCOMPLETE),
                             "detail": "evidence is incomplete (declared "
                                       "missing parents)"})

    # ── checkpoints ────────────────────────────────────────
    checkpoints = []
    for wire in payload["checkpoints"]:
        try:
            checkpoints.append(Checkpoint.from_wire(wire))
        except CheckpointError as exc:
            errors.append({"code": int(exc.code), "detail": str(exc)})
    report["checkpoints"] = len(checkpoints)

    by_domain = {}
    for checkpoint in checkpoints:
        public_key = _resolve(resolver, checkpoint.key_id)
        if public_key is None:
            warnings.append({"code": int(ErrorCode.TIMESTAMP_UNVERIFIED),
                             "detail": "checkpoint key unknown"})
        elif not checkpoint.verify(public_key):
            errors.append({"code": int(ErrorCode.DESCRIPTOR_SIGNATURE_INVALID),
                           "detail": f"checkpoint signature invalid: "
                                     f"{checkpoint.domain_id}#{checkpoint.seq}"})
        chain = by_domain.setdefault(checkpoint.domain_id, [])
        for prior in chain:
            if detect_equivocation(prior, checkpoint):
                errors.append({"code": int(ErrorCode.SPLIT_VIEW),
                               "detail": f"equivocation at "
                                         f"{checkpoint.domain_id}#{checkpoint.seq}"})
        chain.append(checkpoint)

    # ── attestations ───────────────────────────────────────
    attestations = []
    for wire in payload["attestations"]:
        try:
            attestations.append(Attestation.from_wire(wire))
        except AttestationError as exc:
            errors.append({"code": int(exc.code), "detail": str(exc)})
    report["attestations"] = len(attestations)

    cone_roots = {e.cone_root for e in events}
    for attestation in attestations:
        public_key = _resolve(resolver, attestation.key_id)
        if public_key is None:
            warnings.append({"code": int(ErrorCode.TIMESTAMP_UNVERIFIED),
                             "detail": "attestation key unknown"})
        elif not attestation.verify(public_key):
            errors.append({"code": int(ErrorCode.POLICY_REJECTED),
                           "detail": f"attestation signature invalid: "
                                     f"{attestation.attestation_id}"})
        if attestation.target_cone_root and cone_roots and \
                attestation.target_cone_root not in cone_roots:
            warnings.append({"code": int(ErrorCode.CONE_INCOMPLETE),
                             "detail": f"attestation target not in bundle: "
                                       f"{attestation.attestation_id}"})

    # ── evidence + disclosure proofs ───────────────────────
    evidence_items = payload["evidence"]
    if evidence_items:
        if not EvidenceSet.verify_full(evidence_items,
                                       manifest.get("evidence_root", "")):
            errors.append({"code": int(ErrorCode.SEAL_MISMATCH),
                           "detail": "evidence does not match its root"})
    elif manifest.get("evidence_root"):
        errors.append({"code": int(ErrorCode.SEAL_MISMATCH),
                       "detail": "manifest claims evidence that is absent"})

    for bundle in payload["disclosures"]:
        if not EvidenceSet.verify_disclosure(bundle):
            errors.append({"code": int(ErrorCode.DISCLOSURE_PROOF_INVALID),
                           "detail": "selective disclosure proof invalid"})

    # ── timestamps ─────────────────────────────────────────
    for stamp in payload["timestamps"]:
        token = stamp.get("token", b"")
        if not token:
            continue
        if timestamp_verifier is None:
            warnings.append({"code": int(ErrorCode.TIMESTAMP_UNVERIFIED),
                             "detail": "timestamp token not independently "
                                       "verified"})
        else:
            try:
                if not timestamp_verifier(stamp):
                    errors.append({"code": int(ErrorCode.TIMESTAMP_UNVERIFIED),
                                   "detail": "timestamp token rejected"})
            except Exception as exc:
                warnings.append({"code": int(ErrorCode.TIMESTAMP_UNVERIFIED),
                                 "detail": f"timestamp verifier error: {exc}"})

    report["ok"] = not errors
    return report
