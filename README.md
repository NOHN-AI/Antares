# Antares

**Audit and Federation for AI agents.** A small, transport-independent message
layer for the questions A2A, MCP and plain JSON-RPC do not answer:

- **Audit** — signed causal events with cone commitments, so "these are all
  the events" is checkable instead of asserted.
- **Evidence** — Merkle-bound blobs, salted commitments, selective disclosure
  with inclusion proofs.
- **Rebuttable claims** — a decision can be justified, challenged, rebutted
  and adjudicated inside the same log.
- **Attestation** — an auditor's verdict is itself an event, so audits can be
  audited.
- **Federation** — signed domain descriptors, rotation pre-commitment,
  revocation, gateway proofs, loop-free routing.

Antares is **not** a transport. It defines no handshake, session, streams,
frame header, or retransmission. Carry messages over HTTP/3, A2A, MCP,
TCP+TLS, or WebSockets.

## Why

Two questions matter when agents cross organizations:

1. **What exactly decided this, and can I tell it was not edited?** A signed
   event names its actor, its key, its algorithm, its parents and the cone of
   history those parents commit to. A verifier recomputes the cone root; a
   truncated history becomes visible instead of plausible.
2. **Who do I talk to, and is that identity real?** A signed descriptor lists
   gateways and trust anchors; rotation requires the outgoing key to
   pre-commit to the successor, and revocation is signed inside the
   descriptor.

Telemetry can be sampled and dropped. Evidence cannot. Antares is built for
the second category: the output is something a third party can verify
**offline**, without trusting your logs or your infrastructure.

## Install

```bash
pip install antares
```

Runtime dependencies: `cbor2`, `cryptography`. The `antares-verify` console
script is installed with the package.

## Quick start — audit

```python
from antares import AuditLog, AuditEvent, generate_keypair, verify_cone

private_key, public_key = generate_keypair()
log = AuditLog(signing_key=private_key, context_id=b"conversation-1",
               key_id="urn:antares:key:planner")

event = AuditEvent(
    event_id="urn:example:event:1",
    actor_node_id="urn:example:node:planner",
    actor_domain_id="urn:example:domain:us",
    event_type="order.approve",
    rule_id="policy.ap",
    rule_version="1.2",
    observed_at="2026-10-19T10:00:00Z",
    logical_clock=1,
)
log.add(event)
assert log.verify_signature(event, public_key)

report = verify_cone([e.to_wire() for e in log.list_events()])
assert report["ok"] and report["complete"]
```

What `add` enforces:

- no self-parent, no causal cycle (`CAUSAL_CYCLE`);
- at most 8 direct parents (`TOO_MANY_PARENTS`);
- missing parents are signed into `ur`, not silently dropped;
- `cr`/`cs` commit to the parent cone, so later truncation is detectable.

## Quick start — rebuttable claim

```python
from antares import Warrant, CounterEvidence, WarrantLedger

warrant = Warrant(
    warrant_id="w1",
    target_cone_root=event.cone_root,
    target_size=event.cone_size + 1,
    decision_event_id=event.event_id,
    necessity="necessary",
    rule_id="policy.ap",
    asserted_at="2026-10-19T10:00:01Z",
).sign(private_key, "urn:antares:key:planner")

ledger = WarrantLedger()
ledger.add_warrant(warrant)
assert ledger.state_of("w1") == "ASSERTED"

counter = CounterEvidence(
    counter_id="c1", warrant_id="w1",
    counter_cone_root="sha256:" + "11" * 32,
    slot="alternatives", kind="evidence",
    expected="cmt:" + "22" * 32, actual="cmt:" + "33" * 32,
).sign(private_key, "urn:antares:key:planner")

ledger.add_counter(counter)
assert ledger.state_of("w1") == "CHALLENGED"
```

## Quick start — evidence bundle

```python
from antares import EvidenceSet, build_bundle, verify_bundle, write_bundle

evidence = EvidenceSet()
evidence.add(b"invoice-42")
evidence.add(b"chat-log")

data = build_bundle(
    events=log.wire_list(),
    evidence=evidence,
    disclosures=[evidence.disclose([0])],   # share one chunk, prove the set
)
write_bundle("case-42.ant", data)

keys = {"urn:antares:key:planner": public_key}
report = verify_bundle(data, keys)
assert report["ok"]
```

```bash
antares-verify case-42.ant --key urn:antares:key:planner=<hex-pubkey>
```

The bundle carries events, checkpoints, attestations, evidence, disclosure
proofs and timestamp tokens; the manifest hash is checked first, then every
signature, then the causal cone.

## Quick start — federation

```python
import time
from antares import (
    FederationRegistry, DomainDescriptor, Gateway, TrustAnchor,
    sign_descriptor, generate_keypair, key_fingerprint,
)

domain_priv, domain_pub = generate_keypair()
domain = "urn:antares:domain:remote"
registry = FederationRegistry("urn:antares:domain:local")
registry.add_trust_anchor(domain, domain_pub,
                          next_key_hash=key_fingerprint(domain_pub))

now = time.time()
descriptor = DomainDescriptor(
    domain_id=domain, descriptor_version=1,
    valid_from=now - 60, valid_until=now + 3600,
    gateways=[Gateway("http3://gw.example:443", "http3", 10)],
    trust_anchors=[TrustAnchor("urn:antares:key:remote", "ed25519",
                               domain_pub)],
)
sign_descriptor(descriptor, domain_priv)
registry.register(descriptor)
```

## Project layout

```
src/antares/
  types.py         # version, error codes, bounds, algorithms
  cbor_utils.py    # canonical CBOR
  signing.py       # ed25519 + hybrid provider, signature encoding
  envelope.py      # the signed envelope shared by all families
  merkle.py        # RFC 6962 shape, inclusion proofs
  audit.py         # AuditEvent, AuditLog, cone verification
  checkpoint.py    # checkpoints, cross-anchors, split-view detection
  disclosure.py    # salted commitments, evidence sets, proofs
  warrant.py       # warrants, counter-evidence, derived states
  attestation.py   # verdicts with operator-set hashes
  bundle.py        # .ant evidence bundles
  federation.py    # descriptors, rotation, revocation, routing
  cli.py           # antares-verify
  vectors.py       # deterministic conformance vectors
schemas/           # JSON Schemas
tests/             # conformance suite + vectors
ANTARES_SPEC.md    # the specification (v2.1)
CONFORMANCE.md     # requirement list (C/E/A/K/P/D/W/T/B/F/V)
```

## Relationship to other standards

| Standard | Layer | Relationship |
|---|---|---|
| HTTP/3 (QUIC) | Transport | Carries Antares messages. |
| MCP | Tool/resource protocol | Antares adds signed events and identity. |
| A2A | Agent RPC | Antares is the audit/federation layer beneath the call. |
| TLS 1.3 | Channel security | Authenticates the connection; Antares signs the content. |
| SCITT / Sigstore / in-toto | Transparency and attestation | Compatible evidence model. Antares adds causal-cone completeness, rebuttable claims and selective disclosure; an entry-level transparency log remains a valid backend. |

## Compatibility

2.1 is **not** wire-compatible with 2.0: the envelope signs `key_id` and
`algorithm`, moves `ctx` into every message, and replaces the 2.0 payload
digest with the evidence root. A 2.1 verifier rejects `v: "2.0"` rather than
reinterpreting it.

## Conformance

See `CONFORMANCE.md`, `tests/vectors/v2.1.json`, and:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Changelog

- `CHANGELOG_v2.1.md` — evidence closure, rebuttal, disclosure, retention.
- `CHANGELOG_v2.0.md` — redefinition as audit and federation layer.

## License

- Code: Apache License 2.0.
- Specification: CC BY 4.0.
