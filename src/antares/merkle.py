"""Deterministic Merkle trees (RFC 6962 shape, no leaf duplication).

Used for three things:
  - evidence roots    (a set of evidence blobs, order-independent)
  - checkpoint roots  (a set of event wire bytes)
  - cone commitments  (a set of parent cone roots)

Design notes:
  - leaves are hashed as sha256(0x00 || data)
  - interior nodes as sha256(0x01 || left || right)
  - the split point is the largest power of two strictly below the size
    (RFC 6962), so odd subtrees are promoted instead of duplicated.
    Duplicating the last leaf is what makes the classic CVE-2012-2459
    style ambiguity possible; promotion avoids it entirely.
  - the root of a one-leaf tree is that leaf's hash (no wrap-around node),
    which keeps "single blob" and "one-element set" identical.
"""
import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes(data)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_of(hashes: list) -> bytes:
    n = len(hashes)
    if n == 0:
        raise ValueError("cannot build a Merkle root over zero leaves")
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(_root_of(hashes[:k]), _root_of(hashes[k:]))


def merkle_root(data_items) -> bytes:
    """Root over the given leaves, in the order supplied."""
    items = list(data_items)
    return _root_of([leaf_hash(d) for d in items])


def merkle_root_sorted(data_items) -> bytes:
    """Root over a *set*: leaves sorted by their encoded bytes."""
    items = sorted(bytes(d) for d in data_items)
    return merkle_root(items)


def digest_hex(raw: bytes) -> str:
    return "sha256:" + raw.hex()


def merkle_root_hex(data_items) -> str:
    return digest_hex(merkle_root(data_items))


def merkle_root_sorted_hex(data_items) -> str:
    return digest_hex(merkle_root_sorted(data_items))


def _segment_root(hashes: list, lo: int, hi: int) -> bytes:
    """Root of a half-open range, computed without touching any proof."""
    if hi - lo == 1:
        return hashes[lo]
    k = _split(hi - lo)
    return node_hash(_segment_root(hashes, lo, lo + k),
                     _segment_root(hashes, lo + k, hi))


def _path_bits(index: int, size: int) -> list:
    """Branch directions from leaf to root: 0 = left child, 1 = right."""
    bits = []
    lo, hi = 0, size
    while hi - lo > 1:
        k = _split(hi - lo)
        if index < lo + k:
            bits.append(0)
            hi = lo + k
        else:
            bits.append(1)
            lo = lo + k
    bits.reverse()
    return bits


def inclusion_proof(data_items, index: int) -> list:
    """Sibling hashes from leaf `index` up to the root (bottom-up)."""
    items = [bytes(d) for d in data_items]
    if not 0 <= index < len(items):
        raise IndexError("leaf index out of range")
    hashes = [leaf_hash(d) for d in items]
    proof: list = []

    def walk(lo: int, hi: int) -> None:
        if hi - lo == 1:
            return
        k = _split(hi - lo)
        if index < lo + k:
            walk(lo, lo + k)
            proof.append(_segment_root(hashes, lo + k, hi))
        else:
            walk(lo + k, hi)
            proof.append(_segment_root(hashes, lo, lo + k))

    walk(0, len(hashes))
    return proof


def verify_inclusion(data: bytes, index: int, size: int,
                     proof: list, root: bytes) -> bool:
    """Verify that `data` is the leaf at `index` of a tree of `size` leaves."""
    if size <= 0 or not 0 <= index < size:
        return False
    bits = _path_bits(index, size)
    if len(proof) != len(bits):
        return False
    current = leaf_hash(data)
    for is_right, sibling in zip(bits, proof):
        if is_right:
            current = node_hash(sibling, current)
        else:
            current = node_hash(current, sibling)
    return current == root


def proof_to_wire(proof: list) -> list:
    return [h.hex() for h in proof]


def proof_from_wire(wire: list) -> list:
    return [bytes.fromhex(h) for h in wire]
