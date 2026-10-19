"""Salted commitments and selective disclosure (spec §8).

Audit evidence is rarely shareable in full. Every private value is replaced
*at signing time* by ``cmt:sha256(salt || canonical(value))``; the salt is
withheld. Disclosing a value means handing over ``(salt, value)``; the
verifier recomputes the commitment and never needs the rest of the record.

Two layers:
  - `seal` / `reveal`   single value, used for event slots
  - `EvidenceSet`       chunked blobs with a Merkle root and inclusion proofs
"""
import os
from dataclasses import dataclass, field

from .cbor_utils import encode_deterministic
from .merkle import (
    digest_hex,
    inclusion_proof,
    merkle_root,
    merkle_root_sorted,
    proof_from_wire,
    proof_to_wire,
    sha256,
    verify_inclusion,
)
from .types import ErrorCode

SALT_BYTES = 16
COMMIT_TAG = b"antares.commit.v1"
CMT_PREFIX = "cmt:"


class DisclosureError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def _commit_raw(value, salt: bytes) -> bytes:
    return sha256(COMMIT_TAG + bytes(salt) + encode_deterministic(value))


def commit(value, salt: bytes) -> str:
    if len(salt) < SALT_BYTES:
        raise DisclosureError(ErrorCode.SEAL_MISMATCH,
                              "salt must be at least 16 bytes")
    return CMT_PREFIX + _commit_raw(value, salt).hex()


def seal(value, salt: bytes = None):
    """Return ``(commitment, salt)``; the commitment is what gets signed."""
    salt = new_salt() if salt is None else bytes(salt)
    return commit(value, salt), salt


def reveal(commitment: str, salt: bytes, value) -> bool:
    try:
        if not commitment.startswith(CMT_PREFIX):
            return False
        expected = bytes.fromhex(commitment[len(CMT_PREFIX):])
    except (ValueError, AttributeError):
        return False
    return _commit_raw(value, salt) == expected


def seal_map(values: dict, salts: dict = None):
    """Seal a mapping of slot -> value. Returns (commitments, salts)."""
    salts = dict(salts or {})
    commitments = {}
    for name, value in values.items():
        salt = salts.get(name) or new_salt()
        salts[name] = salt
        commitments[name] = commit(value, salt)
    return commitments, salts


def reveal_map(commitments: dict, salts: dict, values: dict) -> dict:
    """Return ``{slot: bool}`` for the slots supplied."""
    out = {}
    for name, value in values.items():
        if name not in commitments or name not in salts:
            out[name] = False
            continue
        out[name] = reveal(commitments[name], salts[name], value)
    return out


@dataclass
class EvidenceSet:
    """Chunked evidence with a set-committed Merkle root."""

    _items: list = field(default_factory=list)   # (salt, data, commitment)

    def add(self, data: bytes, salt: bytes = None) -> str:
        salt = new_salt() if salt is None else bytes(salt)
        commitment = commit(bytes(data), salt)
        self._items.append((salt, bytes(data), commitment))
        return commitment

    def __len__(self) -> int:
        return len(self._items)

    def commitments(self) -> list:
        return [c for _, _, c in self._items]

    def root(self) -> str:
        if not self._items:
            raise DisclosureError(ErrorCode.BODY_INVALID,
                                  "empty evidence set")
        leaves = [bytes.fromhex(c[len(CMT_PREFIX):])
                  for _, _, c in self._items]
        return digest_hex(merkle_root_sorted(leaves))

    def items(self) -> list:
        return list(self._items)

    def disclose(self, indices) -> dict:
        """Subset bundle: values + salts + inclusion proofs only."""
        if not self._items:
            raise DisclosureError(ErrorCode.BODY_INVALID,
                                  "empty evidence set")
        leaves = [bytes.fromhex(c[len(CMT_PREFIX):])
                  for _, _, c in self._items]
        # The committed tree is the *sorted* set; proofs must follow that
        # order, not insertion order.
        order = sorted(range(len(leaves)), key=lambda k: leaves[k])
        sorted_leaves = [leaves[k] for k in order]
        selected = []
        for index in indices:
            salt, data, commitment = self._items[index]
            position = order.index(index)
            proof = inclusion_proof(sorted_leaves, position)
            selected.append({
                "i": position,
                "cmt": commitment,
                "salt": salt,
                "data": data,
                "proof": proof_to_wire(proof),
            })
        return {
            "root": digest_hex(merkle_root(sorted_leaves)),
            "size": len(sorted_leaves),
            "items": selected,
        }

    @staticmethod
    def verify_disclosure(bundle: dict) -> bool:
        """Check values against commitments and each proof against the root."""
        try:
            root = bytes.fromhex(bundle["root"][len("sha256:"):])
            size = int(bundle["size"])
            items = bundle["items"]
        except Exception:
            return False
        if not items or size <= 0:
            return False
        for item in items:
            commitment = item["cmt"]
            salt = item["salt"]
            data = item["data"]
            if not reveal(commitment, salt, data):
                return False
            leaf = bytes.fromhex(commitment[len(CMT_PREFIX):])
            proof = proof_from_wire(item["proof"])
            if not verify_inclusion(leaf, int(item["i"]), size, proof, root):
                return False
        return True

    @staticmethod
    def verify_full(items: list, root_hex: str) -> bool:
        """Check a complete evidence list against a claimed root."""
        try:
            leaves = []
            for item in items:
                if not reveal(item["cmt"], item["salt"], item["data"]):
                    return False
                leaves.append(bytes.fromhex(item["cmt"][len(CMT_PREFIX):]))
        except Exception:
            return False
        if not leaves:
            return False
        return digest_hex(merkle_root_sorted(leaves)) == root_hex


# A small alias kept for callers that think in "commitments" not "cmt:".
def commitment_bytes(commitment: str) -> bytes:
    if not commitment.startswith(CMT_PREFIX):
        raise DisclosureError(ErrorCode.SEAL_MISMATCH,
                              "not a commitment")
    return bytes.fromhex(commitment[len(CMT_PREFIX):])
