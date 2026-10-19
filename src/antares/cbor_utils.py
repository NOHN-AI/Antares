"""Deterministic CBOR encode/decode.

Canonical configuration (spec §3):
- canonical map ordering (lexicographic on the encoded key bytes)
- shortest integer encoding
- no indefinite-length strings or containers
- text is UTF-8, binary is bytes

The signature is always computed over the canonical encoding. JSON is a
presentation convenience only.
"""
import cbor2


def encode_deterministic(obj) -> bytes:
    """Encode any CBOR-representable value to canonical (deterministic) bytes."""
    return cbor2.dumps(obj, canonical=True)


def decode_any(data: bytes):
    """Decode CBOR bytes without imposing a top-level type."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")
    return cbor2.loads(bytes(data))


def decode(data: bytes) -> dict:
    """Decode CBOR bytes to a Python dict (C3)."""
    result = decode_any(data)
    if not isinstance(result, dict):
        raise TypeError(
            f"CBOR payload must decode to dict, got {type(result).__name__}"
        )
    return result


def is_canonical(data: bytes) -> bool:
    """True when `data` is already the canonical encoding of its content."""
    try:
        return encode_deterministic(decode_any(data)) == bytes(data)
    except Exception:
        return False
