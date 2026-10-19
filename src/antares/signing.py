"""Asymmetric signing with algorithm agility.

Supported algorithms (spec §4):
  - ``ed25519``            raw 32-byte keys (default, always available)
  - ``ed25519+ml-dsa-65``  hybrid; requires a cryptography build that
                           exposes ML-DSA. When the provider is missing the
                           library raises ALG_UNAVAILABLE instead of
                           silently downgrading to a single signature.

Signature encoding: hex of the canonical CBOR map ``{component: signature}``.
Uniform across single- and multi-component algorithms so verification never
has to guess the layout.

Key material is raw bytes (ed25519) or ``{component: bytes}`` (hybrid).
Production holds keys in a KMS/HSM; this module keeps the dependency surface
minimal.
"""
from typing import Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .cbor_utils import decode, encode_deterministic
from .types import (
    ALG_COMPONENTS,
    ALG_ED25519,
    ALG_ED25519_MLDSA65,
    ErrorCode,
)


class SigningError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _ml_dsa():
    """Return the ML-DSA module if this cryptography build provides it."""
    try:  # pragma: no cover - depends on the installed wheel
        from cryptography.hazmat.primitives.asymmetric import ml_dsa
        return ml_dsa
    except Exception:
        return None


def require_alg(alg: str) -> None:
    if alg not in ALG_COMPONENTS:
        raise SigningError(ErrorCode.UNKNOWN_ALG, f"unknown alg {alg!r}")
    if alg == ALG_ED25519_MLDSA65 and _ml_dsa() is None:
        raise SigningError(
            ErrorCode.ALG_UNAVAILABLE,
            "ed25519+ml-dsa-65 requires a cryptography build with ML-DSA",
        )


# ── ed25519 primitives (raw 32-byte keys) ──────────────────
def generate_keypair(alg: str = ALG_ED25519):
    """Generate a keypair.

    ed25519 -> ``(priv32, pub32)``; hybrid -> ``({comp: bytes}, {comp: bytes})``.
    """
    require_alg(alg)
    if alg == ALG_ED25519:
        priv = ed25519.Ed25519PrivateKey.generate()
        return (
            priv.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
            priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ),
        )

    ml_dsa = _ml_dsa()  # pragma: no cover - provider dependent
    ed_priv, ed_pub = generate_keypair(ALG_ED25519)
    try:
        ml_priv_obj = ml_dsa.MLDSA65PrivateKey.generate()
        ml_priv = ml_priv_obj.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        ml_pub = ml_priv_obj.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    except Exception as exc:  # pragma: no cover
        raise SigningError(ErrorCode.ALG_UNAVAILABLE, str(exc))
    return (
        {"ed25519": ed_priv, "ml-dsa-65": ml_priv},
        {"ed25519": ed_pub, "ml-dsa-65": ml_pub},
    )


def _ed_sign(private_key: bytes, message: bytes) -> bytes:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return key.sign(message)


def _ed_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, message)
        return True
    except Exception:
        return False


# ── legacy single-signature helpers (ed25519 only) ─────────
def sign(private_key: bytes, message: bytes) -> bytes:
    """Ed25519 signature over `message` (private key is raw 32 bytes)."""
    return _ed_sign(private_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if `signature` is valid for `message` under `public_key`."""
    return _ed_verify(public_key, message, signature)


# ── multi-component API used by the envelope ───────────────
def sign_bytes(alg: str, private_key, message: bytes) -> Dict[str, bytes]:
    require_alg(alg)
    if alg == ALG_ED25519:
        return {"ed25519": _ed_sign(private_key, message)}

    ml_dsa = _ml_dsa()  # pragma: no cover - provider dependent
    components = {"ed25519": _ed_sign(private_key["ed25519"], message)}
    try:
        key = ml_dsa.MLDSA65PrivateKey.from_private_bytes(
            private_key["ml-dsa-65"]
        )
        components["ml-dsa-65"] = key.sign(message)
    except Exception as exc:  # pragma: no cover
        raise SigningError(ErrorCode.ALG_UNAVAILABLE, str(exc))
    return components


def verify_bytes(alg: str, public_key, message: bytes,
                 components: Dict[str, bytes]) -> bool:
    try:
        require_alg(alg)
    except SigningError:
        return False
    if set(components) != set(ALG_COMPONENTS[alg]):
        return False
    if not _ed_verify(public_key["ed25519"] if isinstance(public_key, dict)
                      else public_key, message, components["ed25519"]):
        return False
    if alg == ALG_ED25519:
        return True

    ml_dsa = _ml_dsa()  # pragma: no cover
    try:
        key = ml_dsa.MLDSA65PublicKey.from_public_bytes(
            public_key["ml-dsa-65"]
        )
        key.verify(components["ml-dsa-65"], message)
        return True
    except Exception:
        return False


def encode_signature(components: Dict[str, bytes]) -> str:
    """Hex of canonical CBOR ``{component: signature}``."""
    return encode_deterministic(
        {k: bytes(v) for k, v in components.items()}
    ).hex()


def decode_signature(signature_hex: str) -> Dict[str, bytes]:
    try:
        raw = bytes.fromhex(signature_hex)
        loaded = decode(raw)
    except Exception as exc:
        raise SigningError(
            ErrorCode.BODY_INVALID, f"malformed signature: {exc}"
        )
    if not loaded or not all(
        isinstance(k, str) and isinstance(v, bytes) for k, v in loaded.items()
    ):
        raise SigningError(ErrorCode.BODY_INVALID,
                           "signature components must map str -> bytes")
    return loaded


def key_id_for(identity: str) -> str:
    """Stable key_id for a node or domain."""
    return f"urn:antares:key:{identity}"


def public_key_wire(alg: str, public_key) -> Dict[str, str]:
    """Serialize a public key for descriptors (hex, component-keyed)."""
    if isinstance(public_key, dict):
        return {k: bytes(v).hex() for k, v in public_key.items()}
    return {"ed25519": bytes(public_key).hex()}


def public_key_from_wire(wire: Dict[str, str]):
    if set(wire) == {"ed25519"}:
        return bytes.fromhex(wire["ed25519"])
    return {k: bytes.fromhex(v) for k, v in wire.items()}


class TrustAnchorRegistry:
    """Maps a key_id to a trusted public key."""

    def __init__(self):
        self._keys: Dict[str, object] = {}

    def register(self, key_id: str, public_key) -> None:
        self._keys[key_id] = public_key

    def get(self, key_id: str):
        return self._keys.get(key_id)

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._keys
