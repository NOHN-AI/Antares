# Antares

**Audit and Federation for AI agents.** A small, transport-independent
message layer that provides the two things A2A, MCP, and plain HTTP/JSON-RPC
do not:

- **Audit** — signed causal events, with cycle detection, missing-parent
  tracking, and deterministic state hashing.
- **Federation** — signed domain descriptors, trust-anchor verification, and
  loop-free cross-domain routing.

Antares is **not** a transport. It defines no handshake, session, streams,
frame header, or retransmission. You carry Antares messages over whatever
you already run: HTTP/3, A2A, MCP, TCP+TLS, or WebSockets.

## Why

When agents cross organizations, two questions matter:

1. **What exactly decided this?** A signed causal event answers who produced
   it, what it depended on, and what state it saw — verifiable without
   trusting the operator's logs.
2. **Who do I talk to, and is that identity real?** A signed domain
   descriptor lists gateways and trust anchors; the registry verifies
   signatures, validity windows, and version monotonicity.

A2A and MCP define *how to call* an agent. Antares provides the
non-repudiable evidence and identity layer underneath those calls.

## Install

```bash
pip install antares
```

Runtime dependencies: `cbor2`, `cryptography`.

## Quick start — Audit

```python
from antares import AuditLog, AuditEvent, generate_keypair

private_key, public_key = generate_keypair()
log = AuditLog(signing_key=private_key, context_id=b"conversation-1")

event = AuditEvent(
    event_id="urn:example:event:1",
    actor_node_id="urn:example:node:planner",
    actor_domain_id="urn:example:domain:us",
    event_type="order.approve",
    rule_id="policy.ap",
    rule_version="1.2",
    observed_at="2026-10-18T10:00:00Z",
    logical_clock=1,
)
log.add(event)
assert log.verify_signature(event, public_key)
```

Invariants enforced on `add`:

- no self-parent, no causal cycles (`CAUSAL_CYCLE`);
- at most 8 direct parents (`TOO_MANY_PARENTS`);
- missing parents are recorded in `unresolved_parents`, not rejected.

## Quick start — Federation

```python
import time
from antares import (
    FederationRegistry, DomainDescriptor, Gateway, TrustAnchor,
    sign_descriptor, generate_keypair,
)

domain_priv, domain_pub = generate_keypair()
remote = "urn:antares:domain:remote"

registry = FederationRegistry("urn:antares:domain:local")
registry.add_trust_anchor(remote, domain_pub)

now = time.time()
descriptor = DomainDescriptor(
    domain_id=remote,
    descriptor_version=1,
    valid_from=now - 60,
    valid_until=now + 3600,
    gateways=[Gateway("http3://gw.example:443", "http3", 10)],
    trust_anchors=[TrustAnchor("k1", "ed25519", domain_pub)],
)
sign_descriptor(descriptor, domain_priv)
registry.register(descriptor)

route = registry.route_query(
    target_domain=remote, visited_domains=[], max_hops=4
)
print(route["next_hop"])
```

The registry rejects expired, stale-version, and unsigned descriptors, and
`route_query` enforces hop limits and visited-domain loop detection.

## Project layout

```
src/antares/
  types.py        # version, error codes, bounds
  cbor_utils.py   # canonical CBOR
  signing.py      # Ed25519 keypairs, sign/verify, trust anchors
  audit.py        # AuditEvent, AuditLog
  federation.py   # DomainDescriptor, FederationRegistry
  business.py     # deterministic handler protocol + state hashing
tests/            # 15-case unittest suite
schemas/          # JSON Schemas for the two messages
ANTARES_SPEC.md   # message specification
```

## Relationship to other standards

| Standard | Layer | Relationship |
|---|---|---|
| HTTP/3 (QUIC) | Transport | Carries Antares messages. |
| MCP | Tool/resource protocol | Antares adds signed events and identity. |
| A2A | Agent RPC | Antares provides the audit/federation layer. |
| TLS 1.3 | Channel security | Authenticates the connection; Antares signs the content. |

## Conformance

See `CONFORMANCE.md` and the test suite. An implementation is conformant if
it produces canonical CBOR, enforces the causal invariants, and verifies
descriptor signatures and routing rules as specified.

## Changelog

See `CHANGELOG_v2.0.md`.

## License

- Code: Apache License 2.0.
- Specification: CC BY 4.0.
