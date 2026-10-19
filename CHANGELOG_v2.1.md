# Changelog — v2.1

## 2.1 — Evidence closure, rebuttal, disclosure, retention

v2.1 keeps the 2.0 scope (audit + federation, transport-independent) and
closes the gaps that made 2.0 a log format rather than an audit protocol.

### Fixed (breaking)

- **Context was outside the message.** `ctx` lived in the `AuditLog`
  constructor but participated in the signature, so a third party could not
  verify an event without the producing log. It now travels in every message.
- **Key identity was unsigned.** `actor_node_id` was a free string while the
  signature covered no key reference: any key could claim any actor. The
  envelope now signs `k` (key id) and `a` (algorithm).
- **The payload digest committed to nothing.** 2.0 computed
  `sha256(f"{event_type}:{result_code}")` — both fields were already in the
  header. It is replaced by the evidence Merkle root `er`, which commits to
  the actual evidence and its chunk count `en`.
- **`unresolved_parents` was unsigned.** It is now the signed field `ur`, so
  a claim of incompleteness cannot appear or disappear after the fact.

### Added

- **Signed envelope** shared by all message families, with domain separation
  (`m`), version pinning (`v`), strict wire key set, and a uniform
  component-keyed signature encoding.
- **Causal cone commitment** (`cr`, `cs`) and a completeness report that
  distinguishes *forged* evidence from *incomplete* evidence.
- **Checkpoints** with split-view detection (`SPLIT_VIEW`) and cross-anchoring
  between independent domains.
- **Evidence Merkle trees** (RFC 6962 shape, odd promotion, no duplicate
  leaves), with inclusion proofs and set-ordered roots.
- **Salted commitments and selective disclosure**, including `.ant` bundles
  that a third party can verify offline.
- **Rebuttable claims**: `Warrant`, `CounterEvidence`, rebuttal and
  adjudication, with states derived from the message set.
- **Attestation** with an operator-set hash, and conversion of a verdict into
  an audit event so the audit itself is auditable.
- **Federation hardening**: rotation pre-commitment (`nx`), signed
  revocations evaluated at observation time, gateway proof of possession,
  algorithm agility with an explicit `ALG_UNAVAILABLE` failure.
- **`antares-verify` CLI** and byte-level conformance vectors.
- **`MAX_PARENT_EVENTS` stays 8**, but fan-in is no longer a hard ceiling on
  evidence: the cone root, not the parent list, carries history.

### Deliberately not added

- A judgement function for "was this decision necessary". Only the evidence
  slots, the challenge mechanism and the state machine are specified;
  profiles constrain vocabulary, the algorithm stays in the implementing
  product.
- Network fetch, gossip, and multi-hop path computation. These are transport
  or profile concerns, and pretending otherwise is how audit protocols turn
  into half-built transports.

## 2.0 — Redefinition as audit and federation layer

See `CHANGELOG_v2.0.md`. Removed the GFSIP transport shell (frames, session
state machine, ACK/retransmit), renamed `gfsip` → `antares`, moved to a `src/`
layout, replaced placeholder HMAC with Ed25519.

## 1.x — Legacy

The earlier v1.0/v1.1 GFSIP transport work remains in the Git history.
