"""`antares-verify` — offline verifier for bundles and single messages.

    antares-verify evidence.ant --keys keys.json
    antares-verify event.cbor --keys keys.json --json

Key file format (JSON object, either form per entry)::

    { "urn:antares:key:...": "hex-of-32-byte-ed25519-public-key" }
    { "urn:antares:key:...": {"ed25519": "hex", "ml-dsa-65": "hex"} }

Exit codes: 0 verified, 1 findings, 2 usage/IO error.
"""
import argparse
import json
import sys

from .audit import AuditEvent, verify_cone
from .bundle import MAGIC, read_bundle, verify_bundle
from .cbor_utils import decode_any
from .checkpoint import Checkpoint
from .envelope import Envelope, EnvelopeError
from .federation import DomainDescriptor
from .signing import public_key_from_wire
from .types import MSG_ATTESTATION, MSG_CHECKPOINT, MSG_DESCRIPTOR, MSG_EVENT

MESSAGE_LABELS = {
    MSG_EVENT: "audit.event",
    MSG_CHECKPOINT: "audit.checkpoint",
    MSG_ATTESTATION: "audit.attestation",
    MSG_DESCRIPTOR: "federation.descriptor",
}


def load_keys(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    keys = {}
    for key_id, value in raw.items():
        if isinstance(value, str):
            keys[key_id] = bytes.fromhex(value)
        elif isinstance(value, dict):
            keys[key_id] = public_key_from_wire(value)
        else:
            raise ValueError(f"bad key entry for {key_id}")
    return keys


def parse_key_args(items) -> dict:
    keys = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"--key expects kid=hex, got {item!r}")
        key_id, hex_value = item.split("=", 1)
        keys[key_id.strip()] = bytes.fromhex(hex_value.strip())
    return keys


def _single_message(data: bytes, keys: dict) -> dict:
    report = {"ok": False, "kind": "message", "errors": [], "warnings": []}
    try:
        wire = decode_any(data)
        envelope = Envelope.from_wire(wire)
    except EnvelopeError as exc:
        report["errors"].append({"code": int(exc.code), "detail": str(exc)})
        return report
    except Exception as exc:
        report["errors"].append({"code": 2010,
                                 "detail": f"cannot decode: {exc}"})
        return report

    report["message"] = envelope.msg
    report["key_id"] = envelope.key_id
    report["algorithm"] = envelope.alg
    public_key = keys.get(envelope.key_id)
    if public_key is None:
        report["warnings"].append({"code": 2025,
                                   "detail": "public key not supplied"})
        report["ok"] = False
        return report
    report["signature_valid"] = envelope.verify(public_key)

    if envelope.msg == MSG_EVENT and report["signature_valid"]:
        event = AuditEvent.from_wire(wire)
        report["event_id"] = event.event_id
        report["cone"] = verify_cone([wire])
    elif envelope.msg == MSG_DESCRIPTOR:
        report["domain"] = DomainDescriptor.from_wire(wire).domain_id
    elif envelope.msg == MSG_CHECKPOINT:
        report["checkpoint"] = Checkpoint.from_wire(wire).seq

    report["ok"] = bool(report.get("signature_valid")) and not report["errors"]
    return report


def _print_human(report: dict) -> None:
    if report.get("kind") == "bundle":
        print(f"bundle: {report.get('events', 0)} event(s), "
              f"{report.get('checkpoints', 0)} checkpoint(s), "
              f"{report.get('attestations', 0)} attestation(s)")
        cone = report.get("cone") or {}
        if cone:
            print(f"cone: complete={cone.get('complete')} "
                  f"ok={cone.get('ok')}")
        for warning in report.get("warnings", []):
            print(f"warning [{warning['code']}]: {warning['detail']}")
        for error in report.get("errors", []):
            print(f"error   [{error['code']}]: {error['detail']}")
        print("VERIFIED" if report.get("ok") else "NOT VERIFIED")
        return

    print(f"message: {report.get('message', '?')} "
          f"key: {report.get('key_id', '?')} "
          f"alg: {report.get('algorithm', '?')}")
    for warning in report.get("warnings", []):
        print(f"warning [{warning['code']}]: {warning['detail']}")
    for error in report.get("errors", []):
        print(f"error   [{error['code']}]: {error['detail']}")
    print("VERIFIED" if report.get("ok") else "NOT VERIFIED")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="antares-verify",
        description="Verify an Antares evidence bundle or single message.",
    )
    parser.add_argument("path", help="bundle (.ant) or CBOR message file")
    parser.add_argument("--keys", help="JSON file mapping key_id to public key")
    parser.add_argument("--key", action="append", default=[],
                        metavar="KID=HEX",
                        help="inline public key (repeatable)")
    parser.add_argument("--require-keys", action="store_true",
                        help="treat unknown keys as errors, not warnings")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    try:
        keys = {}
        if args.keys:
            keys.update(load_keys(args.keys))
        keys.update(parse_key_args(args.key))
    except (OSError, ValueError) as exc:
        print(f"cannot load keys: {exc}", file=sys.stderr)
        return 2

    try:
        data = read_bundle(args.path)
    except OSError as exc:
        print(f"cannot read {args.path}: {exc}", file=sys.stderr)
        return 2

    if data.startswith(MAGIC):
        report = verify_bundle(data, keys, require_keys=args.require_keys)
        report["kind"] = "bundle"
    else:
        report = _single_message(data, keys)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0 if report.get("ok") else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
