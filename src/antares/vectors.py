"""Deterministic test vectors (spec §14).

Without byte-level vectors a specification cannot be implemented twice and
compared. Everything here is derived from fixed seeds, so any conformant
implementation must reproduce these exact bytes.

    python -m antares.vectors --out tests/vectors/v2.1.json
"""
import argparse
import json

from .attestation import operator_set_hash
from .audit import AuditEvent, AuditLog, evidence_root_of
from .cbor_utils import encode_deterministic
from .disclosure import seal
from .merkle import inclusion_proof, merkle_root_hex, proof_to_wire
from .signing import generate_keypair
from .types import ALG_ED25519, SPEC_VERSION

FIXED_PRIVATE_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
FIXED_PRIVATE_KEY_2 = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
CONTEXT = b"ctx-alpha"
KEY_ID = "urn:antares:key:alpha"
DOMAIN = "urn:antares:domain:alpha"
NODE = "urn:antares:node:alpha"
OBSERVED_AT = "2026-10-19T00:00:00Z"

MERKLE_LEAVES = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
MANIFEST = [
    {"n": "NS", "l": "T0", "i": 0},
    {"n": "IAP", "l": "T0", "i": 1},
    {"n": "BFC", "l": "T1", "i": 2},
    {"n": "ACC", "l": "T2", "i": 3},
]


def _public_key(private_key: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def build_vectors() -> dict:
    _, _ = generate_keypair(ALG_ED25519)  # keep the RNG path exercised

    log = AuditLog(signing_key=FIXED_PRIVATE_KEY, context_id=CONTEXT,
                   key_id=KEY_ID)
    evidence = [b"evidence-1", b"evidence-2"]
    event = AuditEvent(
        event_id="urn:antares:event:0001",
        parent_event_ids=[],
        actor_node_id=NODE,
        actor_domain_id=DOMAIN,
        event_type="order.approve",
        rule_id="policy.ap",
        rule_version="1.2",
        state_before_hash="sha256:" + "11" * 32,
        state_after_hash="sha256:" + "22" * 32,
        evidence_root=evidence_root_of(evidence),
        evidence_count=len(evidence),
        result_code="ok",
        observed_at=OBSERVED_AT,
        logical_clock=1,
    )
    log.add(event)
    wire = event.to_wire()

    commitment, salt = seal({"amount": 42}, salt=bytes(range(16)))

    return {
        "spec_version": SPEC_VERSION,
        "keys": {
            KEY_ID: _public_key(FIXED_PRIVATE_KEY),
            "urn:antares:key:beta": _public_key(FIXED_PRIVATE_KEY_2),
        },
        "event": {
            "wire_cbor_hex": encode_deterministic(wire).hex(),
            "signed_bytes_hex": event.to_envelope().signed_bytes().hex(),
            "signature_hex": event.signature,
            "cone_root": event.cone_root,
            "cone_size": event.cone_size,
            "evidence_root": event.evidence_root,
        },
        "merkle": {
            "leaves_hex": [leaf.hex() for leaf in MERKLE_LEAVES],
            "root": merkle_root_hex(MERKLE_LEAVES),
            "index": 3,
            "proof_hex": proof_to_wire(
                inclusion_proof(MERKLE_LEAVES, 3)
            ),
        },
        "commitment": {
            "salt_hex": salt.hex(),
            "value": {"amount": 42},
            "commitment": commitment,
        },
        "operator_set": {
            "manifest": MANIFEST,
            "hash": operator_set_hash(MANIFEST),
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="antares.vectors")
    parser.add_argument("--out", required=True, help="output JSON path")
    args = parser.parse_args(argv)
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(build_vectors(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
