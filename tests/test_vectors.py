"""Byte-level conformance vectors (spec §14).

These tests fail if any implementation change alters the wire format,
the canonical encoding, the signature input, or a derived root.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from antares import (
    AuditEvent,
    decode_any,
    encode_deterministic,
    inclusion_proof,
    merkle_root_hex,
    operator_set_hash,
    reveal,
    verify_inclusion,
)
from antares.merkle import proof_from_wire

VECTOR_PATH = os.path.join(os.path.dirname(__file__), "vectors", "v2.1.json")


def load_vectors() -> dict:
    with open(VECTOR_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()

    def test_spec_version(self):
        self.assertEqual(self.vectors["spec_version"], "2.1")

    def test_canonical_encoding_is_stable(self):
        wire = decode_any(bytes.fromhex(
            self.vectors["event"]["wire_cbor_hex"]
        ))
        self.assertEqual(encode_deterministic(wire).hex(),
                         self.vectors["event"]["wire_cbor_hex"])

    def test_signature_bytes_are_stable(self):
        wire = decode_any(bytes.fromhex(
            self.vectors["event"]["wire_cbor_hex"]
        ))
        event = AuditEvent.from_wire(wire)
        self.assertEqual(event.to_envelope().signed_bytes().hex(),
                         self.vectors["event"]["signed_bytes_hex"])
        self.assertEqual(event.signature,
                         self.vectors["event"]["signature_hex"])

    def test_signature_verifies_with_published_key(self):
        wire = decode_any(bytes.fromhex(
            self.vectors["event"]["wire_cbor_hex"]
        ))
        event = AuditEvent.from_wire(wire)
        public_key = bytes.fromhex(self.vectors["keys"][event.key_id])
        self.assertTrue(event.to_envelope().verify(public_key))

    def test_cone_and_evidence_roots_are_stable(self):
        wire = decode_any(bytes.fromhex(
            self.vectors["event"]["wire_cbor_hex"]
        ))
        event = AuditEvent.from_wire(wire)
        self.assertEqual(event.cone_root, self.vectors["event"]["cone_root"])
        self.assertEqual(event.cone_size, self.vectors["event"]["cone_size"])
        self.assertEqual(event.evidence_root,
                         self.vectors["event"]["evidence_root"])

    def test_merkle_root_and_proof_are_stable(self):
        merkle = self.vectors["merkle"]
        leaves = [bytes.fromhex(leaf) for leaf in merkle["leaves_hex"]]
        self.assertEqual(merkle_root_hex(leaves), merkle["root"])
        root = bytes.fromhex(merkle["root"][len("sha256:"):])
        index = merkle["index"]
        proof = proof_from_wire(merkle["proof_hex"])
        self.assertTrue(verify_inclusion(leaves[index], index, len(leaves),
                                         proof, root))
        self.assertEqual(
            [h.hex() for h in inclusion_proof(leaves, index)],
            merkle["proof_hex"],
        )

    def test_commitment_is_stable(self):
        vector = self.vectors["commitment"]
        self.assertTrue(reveal(vector["commitment"],
                               bytes.fromhex(vector["salt_hex"]),
                               vector["value"]))

    def test_operator_set_hash_is_stable(self):
        vector = self.vectors["operator_set"]
        self.assertEqual(operator_set_hash(vector["manifest"]),
                         vector["hash"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
