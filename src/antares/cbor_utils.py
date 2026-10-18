"""Deterministic CBOR encode/decode.
Uses cbor2 with canonical configuration:
- canonical map ordering
- shortest encoding for integers
- no indefinite-length strings or containers
"""
import cbor2


def encode_deterministic(obj: dict) -> bytes:
    """Encode a dict to canonical CBOR bytes."""
    return cbor2.dumps(obj, canonical=True)


def decode(data: bytes) -> dict:
    """Decode CBOR bytes to a Python dict."""
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")
    result = cbor2.loads(data)
    if not isinstance(result, dict):
        raise TypeError(
            f"CBOR payload must decode to dict, got {type(result).__name__}"
        )
    return result
