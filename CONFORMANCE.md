# Conformance

This document lists the conformance requirements for an Antares v2.0
implementation. The canonical test suite in `tests/` exercises every item.

## Canonical encoding

- C1: Signed bytes MUST be canonical CBOR (`cbor2.dumps(..., canonical=True)`).
- C2: Maps use lexicographic key order; integers use shortest encoding.
- C3: Decoding a payload that does not produce a dict MUST fail.

## Audit

- A1: An event listing itself as a parent is rejected with `CAUSAL_CYCLE`.
- A2: A new event that would create a cycle (DFS over known parent/child
  edges reaches the new event) is rejected with `CAUSAL_CYCLE`.
- A3: More than 8 direct parents is rejected with `TOO_MANY_PARENTS`.
- A4: Missing parents are recorded in `unresolved_parents`; the event is
  still accepted.
- A5: Without an Ed25519 signing key, `add` fails with
  `MISSING_SIGNING_KEY`.
- A6: The signature covers the canonical CBOR structure described in
  `ANTARES_SPEC.md` section 4.2.
- A7: Tampering with a signed field makes verification return false.

## Federation

- F1: Descriptors outside the validity window are rejected with
  `DESCRIPTOR_EXPIRED`.
- F2: A descriptor version not greater than the cached version is rejected
  with `DESCRIPTOR_VERSION_STALE`.
- F3: A descriptor without a configured trust anchor, or with an invalid
  signature, is rejected with `DESCRIPTOR_SIGNATURE_INVALID`.
- F4: `route_query` with `max_hops <= 0` raises `ROUTE_HOP_LIMIT`.
- F5: `route_query` with the local domain already in `visited_domains`
  raises `ROUTE_LOOP`.
- F6: Resolved routes return the gateway with the smallest priority value.

## Deterministic state

- D1: Identical state values produce identical `state_hash` outputs.
- D2: The same `(operation, payload, state)` input to a handler produces
  the same result.

## Test reference

Run:

```bash
python tests/test_core.py
```

All 15 tests must pass for a conformant implementation.
