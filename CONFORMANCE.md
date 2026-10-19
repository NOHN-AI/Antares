# Conformance — Antares v2.1

An implementation is conformant when it reproduces the byte-level vectors in
`tests/vectors/v2.1.json` and satisfies the requirements below for the
features it claims. The reference suite in `tests/` exercises every item.

## Canonical encoding

- **C1** Signed bytes MUST be canonical CBOR (`canonical=True`).
- **C2** Maps use lexicographic key order; integers use shortest encoding.
- **C3** Decoding a payload that does not produce a map MUST fail where a map
  is required.
- **C4** Re-encoding a decoded message MUST reproduce the original bytes.

## Envelope

- **E1** The wire key set MUST be exactly `{v,m,c,k,a,b,s}`; unknown or
  missing keys are rejected.
- **E2** `v` MUST be `"2.1"`; a 2.0 envelope MUST be rejected.
- **E3** The signature MUST cover `{v,m,c,k,a,b}`; `s` is excluded.
- **E4** Changing `c`, `k`, `a`, `v`, `m` or any body field MUST invalidate
  the signature.
- **E5** Signatures MUST be `hex(canonical_cbor({component: sig}))`; a
  component set that does not match the algorithm is invalid.
- **E6** An unknown algorithm MUST fail with `UNKNOWN_ALG`; a known algorithm
  without a provider MUST fail with `ALG_UNAVAILABLE` — never degrade to a
  single signature.
- **E7** Message families MUST be domain-separated by `m`: a signature for
  one family MUST NOT verify as another.
- **E8** Every message body MUST be full-form: all keys present, no extras.

## Audit events

- **A1** Self-parent is rejected with `CAUSAL_CYCLE`.
- **A2** A cycle in the known graph is rejected with `CAUSAL_CYCLE`.
- **A3** More than 8 direct parents is rejected with `TOO_MANY_PARENTS`.
- **A4** Missing parents are recorded in `ur` **inside the signed body** and
  the event is still accepted.
- **A5** Signing without a key fails with `MISSING_SIGNING_KEY`.
- **A6** Two different events sharing an `eid` are rejected with
  `DUPLICATE_ENTITY`.
- **A7** `observed_at` MUST NOT be presented as independently verified time.

## Causal cone

- **K1** `cr` is computed over parents sorted by `eid`, using the exact tag
  strings in §6.1; parent declaration order MUST NOT change the root.
- **K2** `cs` equals the number of distinct ancestors.
- **K3** A recomputed root or size that differs from the claim is reported as
  `cone_root_mismatch` and makes the report `ok = false`.
- **K4** A parent absent from the supplied set and absent from `ur` is
  reported as an undeclared missing parent and makes the report `ok = false`.
- **K5** A parent declared in `ur` and absent makes the cone `unverifiable`
  (incomplete), which MUST NOT be reported as a root mismatch.

## Checkpoints

- **P1** `root` is the Merkle root over the sorted event wire bytes and is
  independent of input order.
- **P2** `size` equals the number of distinct committed events.
- **P3** Two checkpoints with equal `(dom, seq)` and different `root`/`size`
  MUST raise `SPLIT_VIEW`.
- **P4** A checkpoint with a lower `seq`, or a `prev` that does not link to
  the previous checkpoint, MUST raise `CHECKPOINT_SEQ_STALE`.
- **P5** A cross-anchor MUST verify only against the exact `(dom, seq, root)`
  it was issued for.

## Evidence and disclosure

- **D1** Merkle leaves are `sha256(0x00||data)`, nodes `sha256(0x01||l||r)`,
  split at the largest power of two strictly below `n`; odd subtrees are
  promoted, never duplicated.
- **D2** Set roots sort their leaves; the root is order-independent.
- **D3** Inclusion proofs MUST verify for every leaf position at sizes 1..8
  and MUST fail for a wrong index.
- **D4** Commitments are `cmt:` + `sha256("antares.commit.v1"||salt||canonical(value))`
  with `len(salt) >= 16`; a short salt is an error.
- **D5** Revealing a different value or salt MUST NOT open the commitment.
- **D6** A disclosure bundle MUST be rejected when a value does not open its
  commitment or a proof does not reach the claimed root.
- **D7** A timestamp token without a verifier MUST be reported as
  `TIMESTAMP_UNVERIFIED`.

## Rebuttable claims

- **W1** A counter-evidence naming an unknown warrant is rejected with
  `WARRANT_STATE_INVALID`.
- **W2** States are derived from the message set; ingest order MUST NOT
  change any state.
- **W3** A warrant with no counter-evidence is `ASSERTED`; with an
  unanswered counter `CHALLENGED`; with an `UPHELD` counter `REJECTED`.
- **W4** A rebuttal (`sup` naming a counter) sets that counter to `REBUTTED`.
- **W5** Nested counter-evidence is rejected.
- **W6** Changing any signed warrant field invalidates verification.

## Attestation

- **T1** `osh` MUST equal the hash of the normalised operator manifest.
- **T2** A manifest whose contents differ from `osh` MUST be rejected.
- **T3** Operator order affects `osh`; two runs with different order are not
  comparable.
- **T4** An attestation MUST be convertible into an audit event whose
  `evidence_root` is the audited cone root and whose `ext` carries `osh`.

## Bundles

- **B1** A file MUST start with `ANTARES1\n` and decode to the exact key set.
- **B2** `bundle_hash` MUST cover the canonical CBOR of the map without
  `manifest`; any content edit MUST fail with `BUNDLE_MANIFEST_MISMATCH`.
- **B3** `event_root` MUST be the Merkle root over the sorted event wires.
- **B4** Every event, checkpoint and attestation signature MUST be checked
  when a key is resolvable.
- **B5** With `require_keys`, an unresolvable key MUST be an error; without
  it, a warning. Unknown keys MUST never be a pass by default.
- **B6** Evidence MUST match `evidence_root`; a manifest claiming absent
  evidence MUST fail.
- **B7** A split view among contained checkpoints MUST fail the bundle.

## Federation

- **F1** A descriptor outside its validity window is rejected with
  `DESCRIPTOR_EXPIRED`.
- **F2** A non-increasing `dv` is rejected with `DESCRIPTOR_VERSION_STALE`.
- **F3** A missing anchor or invalid signature is rejected with
  `DESCRIPTOR_SIGNATURE_INVALID`.
- **F4** A descriptor signed by a key that is neither the anchor nor a
  pre-committed successor is rejected with `ROTATION_UNPROVEN`.
- **F5** Rotation succeeds only when the current anchor's `nx` equals the
  fingerprint of the new key.
- **F6** A descriptor signed by a key revoked at or before the evaluation
  time is rejected with `REVOKED_KEY`.
- **F7** A gateway `pop` MUST verify over `{dom, dv, uri, tr}`; an absent or
  unverifiable proof is reported, and rejected in strict mode with
  `GATEWAY_UNPROVEN`.
- **F8** `route_query` with `max_hops <= 0` raises `ROUTE_HOP_LIMIT`; with the
  local domain already visited it raises `ROUTE_LOOP`.
- **F9** Resolved routes return the gateway with the smallest `pr`.

## Vectors

- **V1** `tests/vectors/v2.1.json` reproduces exactly: event wire CBOR,
  signed bytes, signature, cone root/size, evidence root, Merkle root and
  proof, commitment, operator-set hash.

## Test reference

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -v
```
