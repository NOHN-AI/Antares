# Antares — Audit and Federation Message Layer

**Status:** v2.0
**Scope:** Message formats, canonical encoding, signing, and verification for
two message families — Audit Events and Domain Descriptors.

Antares is **not** a transport protocol. It does not define sessions,
handshakes, streams, flow control, or retransmission. Carry Antares messages
over HTTP/3, A2A, MCP, TCP+TLS, WebSockets, or any authenticated channel.

## 1. Design goals

1. **Signed causal evidence.** Every material decision is an event with
   declared parents, a producing actor, and an Ed25519 signature.
2. **Verifiable federation.** A domain publishes a self-describing, signed
   descriptor listing gateways and trust anchors.
3. **Transport independence.** No sockets, no state machine, no transport
   dependency.
4. **Deterministic encoding.** Canonical CBOR so signatures are reproducible.

## 2. Non-goals

- Encrypting the channel (use TLS, QUIC, or the transport's own security).
- Defining RPC semantics, capability exchange, or agent "skills" (use A2A or
  MCP).
- Ordering or reliability guarantees (the transport provides them).
- Solving distributed consensus.

## 3. Canonical encoding

All signed byte sequences are canonical CBOR produced by

```python
cbor2.dumps(obj, canonical=True)
```

Properties:

- Maps are emitted in lexicographic key order.
- Integers use the shortest encoding.
- No indefinite-length maps, arrays, or strings.
- Text is UTF-8.

JSON representations are documentation and transport convenience; the
signature is always computed over the canonical CBOR form.

## 4. Audit Event

### 4.1 Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `event_id` | string | yes | Unique identifier (URN or UUID). |
| `parent_event_ids` | string[0..8] | yes | Direct declared causal predecessors. |
| `actor_node_id` | string | yes | Producing node. |
| `actor_domain_id` | string | yes | Producing domain. |
| `event_type` | string | yes | Operation family, e.g. `order.ship`. |
| `rule_id` / `rule_version` | string | no | Governing rule reference. |
| `state_before_hash` | string | no | `sha256:` over the pre-state. |
| `state_after_hash` | string | no | `sha256:` over the post-state. |
| `evidence_hash` | string | no | `sha256:` over the evidence blob. |
| `result_code` | string | no | Operation result. |
| `observed_at` | RFC3339 | yes | Observation timestamp. |
| `logical_clock` | integer | yes | Monotonic node-local logical clock. |
| `unresolved_parents` | string[] | derived | Missing parents recorded at add time. |
| `signature` | hex string | yes | Ed25519 signature. |

### 4.2 Signed structure

The signature covers the canonical CBOR of:

```
{
  "ver": "2.0",
  "ctx": <context identifier bytes>,
  "hdr": <event header fields>,
  "ph":  <payload digest>
}
```

The context identifier binds events to a session, conversation, or task.

### 4.3 Causal invariants

1. **No self-parent.** An event cannot list itself as a parent.
2. **Acyclic.** A depth-first traversal of the known graph must never reach
   the new event through its parents.
3. **Bound on fan-in.** At most 8 direct parents.
4. **Missing parents are recorded, not rejected.** They appear in
   `unresolved_parents` and can be resolved later.

Violations of 1–3 raise `CAUSAL_CYCLE` or `TOO_MANY_PARENTS`.

## 5. Domain Descriptor

### 5.1 Fields

| Field | Type | Description |
|---|---|---|
| `domain_id` | string | `urn:antares:domain:<name>`. |
| `descriptor_version` | integer | Monotonically increasing per domain. |
| `valid_from` / `valid_until` | number | Validity window (epoch seconds). |
| `gateways` | Gateway[] | Reachable entry points. |
| `services` | string[] | Offered service URNs. |
| `trust_anchors` | TrustAnchor[] | Keys authorized by the domain. |
| `revocation_endpoints` | string[] | CRL/OCSP-style endpoints. |
| `signature_algorithm` | string | `ed25519`. |
| `signature` | hex string | Ed25519 signature over canonical CBOR. |

A Gateway has `uri`, `transport` (e.g. `http3`, `a2a`, `tcp+tls`),
`priority`, and `profiles`.

### 5.2 Verification

Before accepting a descriptor the registry:

1. Confirms `valid_from <= now <= valid_until`.
2. Confirms the new version is strictly greater than the cached one.
3. Looks up the locally configured trust anchor for `domain_id`.
4. Verifies the Ed25519 signature over the canonical CBOR.

Failure raises `DESCRIPTOR_EXPIRED`, `DESCRIPTOR_VERSION_STALE`, or
`DESCRIPTOR_SIGNATURE_INVALID`.

### 5.3 Routing

`route_query` resolves the next gateway for a target domain:

- `max_hops <= 0` raises `ROUTE_HOP_LIMIT`.
- The local domain already present in `visited_domains` raises
  `ROUTE_LOOP`.
- Unknown domains return `status: unknown`; known domains return the
  highest-priority gateway URI.

## 6. Error codes

| Code | Name | Meaning |
|---|---|---|
| 2000 | POLICY_REJECTED | Generic policy/validation rejection. |
| 2001 | INTERNAL_ERROR | Library-side failure. |
| 2002 | CAUSAL_CYCLE | Self-parent or cycle in the causal graph. |
| 2003 | TOO_MANY_PARENTS | Parent count exceeds 8. |
| 2004 | MISSING_SIGNING_KEY | Cannot sign without a private key. |
| 2005 | DESCRIPTOR_EXPIRED | Descriptor outside validity window. |
| 2006 | DESCRIPTOR_VERSION_STALE | Version did not increase. |
| 2007 | DESCRIPTOR_SIGNATURE_INVALID | Trust anchor or signature failure. |
| 2008 | ROUTE_LOOP | Local domain already in visited list. |
| 2009 | ROUTE_HOP_LIMIT | Hop budget exhausted. |

## 7. Security considerations

- Keep private keys in a KMS/HSM in production. The library only needs raw
  32-byte Ed25519 values at the boundary.
- Descriptor signatures do not authenticate the transport connection; the
  transport must authenticate the peer (TLS, mTLS, or equivalent).
- Canonical encoding is part of the security contract. Re-serialization
  through a non-canonical encoder invalidates verification.
- `unresolved_parents` means an event's evidence is incomplete; consumers
  decide whether such events are acceptable.

## 8. Licensing

- Specification text: CC BY 4.0 (`LICENSE-SPEC.md`).
- Reference implementation: Apache License 2.0 (`LICENSE`).
