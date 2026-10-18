"""Business — deterministic state handlers and state hashing.
Audit events are only as strong as the evidence behind them. This module
provides a handler protocol and a deterministic KV store so an operation
produces reproducible state_before / state_after hashes.
"""
import hashlib
import json
from typing import Any, Tuple

from .cbor_utils import encode_deterministic


def state_hash(state: Any) -> str:
    """sha256 hash of a deterministically-encoded state."""
    return "sha256:" + hashlib.sha256(
        encode_deterministic(state)
    ).hexdigest()


class BusinessHandler:
    """Pluggable side-effect handler.

    Implementations MUST be deterministic: the same (operation, payload,
    state_before) always produces the same (state_after, result).
    """

    def execute(self, operation: str, payload: bytes,
                state: Any) -> Tuple[Any, Any]:
        raise NotImplementedError


class SimpleKVStore(BusinessHandler):
    """Deterministic key-value store used by the test suite.

    Supports `inventory.reserve`: payload is a JSON object with `item` and
    `qty`; state tracks cumulative reserved quantities per item.
    """

    def __init__(self, initial: dict = None):
        self.state = dict(initial or {})

    def execute(self, operation: str, payload: bytes,
                state: Any) -> Tuple[Any, Any]:
        state = dict(state or {})
        if operation == "inventory.reserve":
            try:
                body = json.loads(payload.decode("utf-8")) if payload else {}
            except (ValueError, UnicodeDecodeError):
                body = {}
            item = str(body.get("item", "?"))
            qty = int(body.get("qty", 0))
            reserved = dict(state.get("reserved", {}))
            reserved[item] = reserved.get(item, 0) + qty
            state["reserved"] = reserved
            result = {
                "reserved": item,
                "qty": qty,
                "total": reserved[item],
            }
            return state, result
        return state, {"ok": False, "reason": "unknown_operation"}
