# Antares — Audit and Federation Message Layer

**Status:** v2.1 (supersedes v2.0; the signed envelope changed, see §16)
**Scope:** message formats, canonical encoding, signing, verification, causal
completeness, evidence disclosure, rebuttable claims, attestation, bundles,
and domain federation.

Antares is **not** a transport protocol. It defines no session, handshake,
stream, flow control, or retransmission. Carry Antares messages over HTTP/3,
A2A, MCP, TCP+TLS, WebSockets, or any authenticated channel.

The design target is narrower than "logging": a third party must be able to
decide, **offline and without trusting the operator**, whether a stated
conclusion is supported by the evidence actually supplied, whether the
evidence was truncated, and who committed to what.

---

## 1. Design goals

1. **Self-contained evidence.** A signed message verifies on its own: version,
   context, key identity, algorithm and body all live inside the signature.
2. **Provable completeness.** Every event commits to its parent cone, so an
   omission is detectable instead of merely possible.
3. **Rebuttable conclusions.** A decision claim can be challenged with
   counter-evidence, and the outcome is recorded in the same log.
4. **Selective disclosure.** Evidence can be shown in part, with proofs, under
   salted commitments that were signed from the start.
5. **Auditable audits.** An auditor's verdict is itself a message, therefore
   it can be checkpointed and audited again.
6. **Deterministic encoding.** Canonical CBOR everywhere; reproducible bytes.
7. **Transport independence.** No sockets, no state machine, no transport
   dependency.

## 2. Non-goals

- Encrypting the channel (use TLS/QUIC).
- Defining RPC, capability exchange, or agent "skills" (use A2A or MCP).
- Ordering or reliability guarantees (the transport provides them).
- Distributed consensus.
- **Defining what makes a decision correct.** Antares defines where the
  argument is written and how it is challenged. The judgement function is a
  profile concern and deliberately out of scope (§14).

## 3. Canonical encoding

All signed byte sequences are canonical CBOR produced by
`cbor2.dumps(obj, canonical=True)`:

- maps in lexicographic key order (by encoded key bytes);
- shortest integer encoding;
- no indefinite-length maps, arrays, or strings;
- text is UTF-8, binary is `bytes`.

A decoder MUST reject a payload whose top-level value is not a map where a
map is required. JSON representations are documentation only; the signature
is always over canonical CBOR.

**Full-form rule.** Every message body is emitted with **all** of its keys
present, including fields with empty values. This makes re-encoding exact and
lets a verifier rebuild the signed bytes from any conformant object model.
A body with a missing or extra key is invalid (`BODY_INVALID`).

## 4. Envelope

### 4.1 Wire form

```
{ "v": "2.1", "m": <family>, "c": <ctx bytes>, "k": <key_id>,
  "a": <algorithm>, "b": <body map>, "s": <signature hex> }
```

| Key | Meaning |
|---|---|
| `v` | `"2.1"`. A different value MUST be rejected; no downgrade path. |
| `m` | message family, see §4.2 |
| `c` | context bytes (session, conversation, task); empty bytes allowed |
| `k` | key identifier, resolved to a public key by the verifier |
| `a` | signature algorithm, see §4.4 |
| `b` | body, family-specific |
| `s` | hex of the canonical-CBOR signature map, see §4.3 |

The key set MUST be exactly these seven keys. Unknown keys are rejected:
otherwise unsigned data could travel beside signed data and be mistaken for
evidence.

`k` SHOULD be an explicit key identifier. When a producer omits it, the actor
id is used; production deployments SHOULD NOT rely on that default, because a
rotated key must remain distinguishable from the key it replaced.

### 4.2 Message families (domain separation)

| Family | Purpose |
|---|---|
| `audit.event` | causal evidence event (§5) |
| `audit.checkpoint` | set commitment over events (§7) |
| `audit.checkpoint.anchor` | cross-signature over another domain's checkpoint (§7.3) |
| `audit.warrant` | decision justification claim (§9) |
| `audit.counter_evidence` | challenge to a warrant (§9) |
| `audit.attestation` | auditor verdict (§10) |
| `federation.descriptor` | signed domain descriptor (§12) |
| `federation.gateway.pop` | gateway proof of possession (§12.4) |

Because `m` is inside the signature, a signature produced for one family can
never be replayed as another.

### 4.3 Signature encoding

```
sig_hex = hex( canonical_cbor( { <component>: <signature bytes> } ) )
```

For `ed25519` the map has one entry; for hybrid algorithms one entry per
component. Uniform encoding means the verifier never guesses a layout. A
signature map whose component set does not match the algorithm is invalid.

### 4.4 Algorithm agility

| Algorithm | Components | Status |
|---|---|---|
| `ed25519` | `ed25519` | required |
| `ed25519+ml-dsa-65` | `ed25519`, `ml-dsa-65` | optional; requires a provider |

An implementation that knows an algorithm but has no provider MUST fail with
`ALG_UNAVAILABLE`. **Silent downgrade to a single signature is forbidden** —
that is precisely the failure mode long-retention evidence cannot afford.

### 4.5 Verification

1. Decode CBOR; reject a non-map.
2. Check exact key set, `v`, and field types.
3. Resolve `k` to a public key. Resolution failure is a rejection, never a
   pass; callers may downgrade it to a warning explicitly.
4. Recompute the signed bytes across `{v,m,c,k,a,b}`.
5. Verify `s` against the resolved key and `a`.
6. Optionally assert `m` and `c` match caller expectations.

## 5. Audit event

### 5.1 Body

| Key | Type | Req | Meaning |
|---|---|---|---|
| `eid` | str | yes | unique event id (URN or UUID) |
| `par` | str[0..8] | yes | declared direct parents |
| `an` | str | yes | producing node |
| `ad` | str | yes | producing domain |
| `typ` | str | yes | operation family, e.g. `order.ship` |
| `rid` / `rv` | str | yes | governing rule id / version (may be empty) |
| `sb` / `sa` | str | yes | `sha256:` over pre/post state (may be empty) |
| `er` | str | yes | evidence Merkle root (§8) or empty |
| `en` | int | yes | number of evidence chunks committed by `er` |
| `rc` | str | yes | result code |
| `ob` | str | yes | observation timestamp, RFC 3339 |
| `lc` | int | yes | node-local logical clock |
| `ur` | str[] | yes | parents missing at add time — **signed** |
| `cr` | str | yes | cone root over known parents (§6) |
| `cs` | int | yes | number of ancestors committed by `cr` |
| `sl` | map | yes | slot name -> seal commitment (§8.3) |
| `ts` | str | yes | digest of an external timestamp token, or empty |
| `x` | map | yes | extension map (profiles); canonical, unsigned keys forbidden |

`ur` is inside the body. A producer that claims incompleteness cannot later
deny it, and a verifier cannot be told to ignore it.

### 5.2 Invariants on add

1. No self-parent.
2. No cycle in the known graph (`CAUSAL_CYCLE`).
3. At most 8 direct parents (`TOO_MANY_PARENTS`).
4. Missing parents are recorded in `ur`, not rejected.
5. Duplicate `eid` with different content is `DUPLICATE_ENTITY`.

### 5.3 Time

`ob` and `lc` are **self-asserted**. Antares does not turn them into trusted
time; that requires an external token (`ts`, §8.5) or checkpoint anchoring
(§7). Consumers MUST NOT present `ob` as independently established time.

## 6. Causal cone and completeness

### 6.1 Cone root

For an event with known parents `P = {(eid_i, cr_i)}`, sorted by `eid`:

```
pnode_i = SHA256( "antares.pnode.v1" || eid_i || "|" || cr_i )
cr      = "sha256:" || hex( SHA256( "antares.cone.v1" || u8(|P|) || pnode_1 || … || pnode_n ) )
cs      = |union of ancestors of P, plus P themselves|
```

Genesis (`|P| = 0`) is the root of `"antares.cone.v1" || 0x00`. Parent
declaration order never affects the root; the sorted order is normative.

### 6.2 Why it matters

A log can always be truncated. Without a commitment to the *shape* of
history, "here are the events" and "here are all the events" are
indistinguishable. `cr` makes the second claim checkable: a verifier that
holds the parents recomputes the root and compares.

### 6.3 Completeness report

Verification over a supplied subgraph returns:

| Outcome | Meaning |
|---|---|
| `cone_root_mismatch` | recomputed root or size differs from the claim → forgery |
| `undeclared_missing_parents` | parent absent but not declared in `ur` → truncation |
| `unverifiable` | parent declared missing → the root cannot be recomputed |
| `complete` | every parent present and every root reproduced |

`ok = true` requires no mismatch and no undeclared missing parent. An
`unverifiable` cone is **incomplete, not false**; policies decide whether to
accept incomplete evidence, and the distinction must remain visible.

## 7. Checkpoints

### 7.1 Body

| Key | Meaning |
|---|---|
| `dom` | domain id |
| `seq` | monotonically increasing checkpoint number |
| `size` | number of events committed |
| `root` | Merkle root over the sorted event wire bytes |
| `prev` | `wire_hash` of the previous checkpoint, or empty |
| `at` | asserted anchor time |
| `anch` | cross-anchor wires (§7.3) |

`wire_hash` is `sha256:` over the canonical CBOR of the signed envelope,
including `s`.

### 7.2 Split view

Two checkpoints with the same `dom` and `seq` but different `root` or `size`
are **proof of equivocation** (`SPLIT_VIEW`), not a benign race. A store MUST
reject the second one and SHOULD retain both as evidence.

### 7.3 Cross-anchoring

An independent domain signs:

```
{ "dom": <checkpoint domain>, "seq": <seq>, "root": <root>, "by": <anchoring domain> }
```

inside `audit.checkpoint.anchor`. Cross-anchors let two mutually distrusting
parties detect a rollback without a shared authority, and give a checkpoint a
second, independent existence.

## 8. Evidence and selective disclosure

### 8.1 Merkle construction

RFC 6962 shape with no leaf duplication:

```
leaf  = SHA256(0x00 || data)
node  = SHA256(0x01 || left || right)
split = largest power of two strictly less than n
```

Odd subtrees are promoted, never duplicated, which removes the classic
duplicate-leaf ambiguity. Set commitments sort their leaves first, so the
root is order-independent.

### 8.2 Evidence root

`er` is the Merkle root over the evidence chunks; `en` is the chunk count.
Chunks are opaque bytes. A producer that stores evidence elsewhere may commit
to a single blob digest instead:

```
er = SHA256("antares.evidence.v1" || digest_bytes)
```

### 8.3 Sealed slots

Private values are replaced at signing time by:

```
cmt = "cmt:" || hex( SHA256("antares.commit.v1" || salt || canonical(value)) )
```

with `len(salt) >= 16` and a fresh random salt per value. The signed body
contains only the commitment. Disclosing the value means handing over
`(salt, value)`; the verifier recomputes the commitment and never needs the
rest of the record.

### 8.4 Selective disclosure bundle

```
{ "root": <evidence root>, "size": n,
  "items": [ { "i": position, "cmt": ..., "salt": ..., "data": ...,
               "proof": [sibling hashes] } ] }
```

Verification checks two things per item: the value opens the commitment, and
the commitment is the leaf at `i` in a tree of `size` with the claimed root.
Confirmed disclosure is therefore a proof about the **set**, not a courtesy
from the holder.

### 8.5 Timestamps

`ts` (and bundle timestamp entries) bind an external token, e.g. an RFC 3161
response. Antares does not re-implement TSA validation: the token is carried
and the verdict is delegated to a verifier. **An unverified token MUST be
reported as unverified** (`TIMESTAMP_UNVERIFIED`); treating bytes as proof is
forbidden.

## 9. Rebuttable claims

Antares does not decide whether a decision was necessary. It defines the
argument's shape so the argument can be replayed.

### 9.1 Warrant

| Key | Meaning |
|---|---|
| `wid` | warrant id |
| `tar` / `tsz` | cone root / size of the audited decision |
| `dec` | decision event id |
| `nec` | `undeclared` \| `necessary` \| `sufficient` \| `necessary_and_sufficient` |
| `rid` / `rv` | rule reference |
| `csh` | commitment to the constraint set used |
| `sl` | slot name -> commitment (the evidence slots) |
| `sup` | counter-evidence id this warrant answers, or empty |
| `at` | asserted time |

`sl` is the extension seam: a profile names the slots (e.g. `alternatives`,
`constraints`, `observed_state`), and the producing engine fills them. The
protocol only fixes the container and the commitment rules.

### 9.2 Counter-evidence

| Key | Meaning |
|---|---|
| `cid` | counter id |
| `wid` | challenged warrant |
| `tar` / `tsz` | cone root / size of the contradicting history |
| `sol` | slot being contradicted |
| `kind` | `state` \| `evidence` \| `rule` \| `timestamp` |
| `exp` / `act` | expected vs actual commitment |
| `note` | commitment to a free-form explanation |

A challenge must point at a slot and supply a competing cone. "I disagree"
without evidence is not a message the protocol can carry.

### 9.3 State machine

States are **derived from the message set**, never stored as mutable flags,
so ingest order cannot change the result.

| Condition on warrant W | State |
|---|---|
| no counter-evidence | `ASSERTED` |
| W answers some counter (`sup` set) | `REBUTTED` |
| ≥1 counter `ASSERTED` | `CHALLENGED` |
| ≥1 counter `UPHELD` | `REJECTED` |
| all counters `REBUTTED` or `DISMISSED` | `REBUTTED` |

| Condition on counter C | State |
|---|---|
| adjudicated `upheld` | `UPHELD` |
| adjudicated `dismissed` | `DISMISSED` |
| named by some warrant's `sup` | `REBUTTED` |
| otherwise | `ASSERTED` |

Nested counters (a counter against a counter) are not defined in 2.1 and MUST
be rejected (`WARRANT_STATE_INVALID`). Conflicts that cannot be resolved
resolve to `CHALLENGED`, never to a silent winner.

### 9.4 Adjudication

Adjudication is an `audit.attestation` with `kind = "adjudicate"`, `tar`
pointing at the counter-evidence id, and `vd` in `{upheld, dismissed}`.

## 10. Attestation

| Key | Meaning |
|---|---|
| `aid` | attestation id |
| `kind` | `audit` \| `adjudicate` |
| `tar` / `tsz` | audited cone root / size |
| `aud` | auditor domain |
| `om` | operator manifest: `[{ "n": name, "l": layer, "i": index }]` |
| `osh` | operator-set hash, see below |
| `vd` | `pass` \| `block` \| `undecided` |
| `fr` | findings Merkle root |
| `sup` | superseded attestation, or empty |
| `at` | asserted time |

```
osh = "sha256:" || hex( SHA256("antares.operatorset.v1" || canonical(om_sorted_by_i)) )
```

`osh` answers "which pipeline produced this verdict". Two verdicts are only
comparable when their `osh` agree, and a tampered manifest breaks the hash.

**Recursion.** `Attestation.to_event()` yields an ordinary audit event whose
`evidence_root` is the audited cone root and whose `ext` carries `osh`, so a
verdict can be checkpointed, audited, and challenged like any other event.
That is the mechanism by which "who audits the auditor" stops being a
promise.

## 11. Evidence bundle (`.ant`)

### 11.1 File

```
"ANTARES1\n" || canonical_cbor(map)
```

```
{ "v", "created_at",
  "events": [event wire], "checkpoints": [wire],
  "attestations": [wire],
  "evidence": [ { "cmt", "salt", "data" } ],
  "disclosures": [ disclosure bundle ],
  "timestamps": [ { "target", "kind", "token" } ],
  "manifest": { "counts", "event_root", "evidence_root", "bundle_hash" } }
```

```
bundle_hash = "sha256:" || hex( SHA256("antares.bundle.v1" || canonical(map without "manifest")) )
event_root  = Merkle root over the sorted canonical event wire bytes
```

### 11.2 Verification order

1. Magic, CBOR, exact key set.
2. Recompute `bundle_hash`; mismatch is fatal (`BUNDLE_MANIFEST_MISMATCH`).
3. Every event signature; unknown keys are rejected unless the caller
   explicitly downgrades them to warnings.
4. Cone verification over the contained events (§6.3).
5. Checkpoint signatures and split-view check per domain.
6. Attestation signatures; `osh` consistency; targets present in the bundle.
7. Evidence root, then each disclosure proof.
8. Timestamp tokens, reported as unverified when no verifier is supplied.

A bundle is verified when no error survives. Warnings are part of the output:
"verified with an unverified timestamp" and "verified" are different claims.

## 12. Federation

### 12.1 Descriptor body

| Key | Meaning |
|---|---|
| `dom` | `urn:antares:domain:<name>` |
| `dv` | descriptor version, strictly increasing per domain |
| `vf` / `vu` | validity window (epoch seconds) |
| `gw` | gateways: `{uri, tr, pr, pf, pop}` |
| `sv` | offered service URNs |
| `ta` | trust anchors: `{kid, alg, pk, vf, vu, nx}` |
| `rev` | revocations: `{kid, at, rs}` |

The envelope's `k` is the descriptor signing key; `c` is the domain id UTF-8.

### 12.2 Anchor fields

`pk` is `{component: hex}` (the same shape for single and hybrid keys).
`nx` is the fingerprint of the **successor** key:

```
fingerprint = "sha256:" || hex( SHA256("antares.key.v1" || canonical({component: pub_hex})) )
```

### 12.3 Rotation

A registry accepts a descriptor signed by a key other than the current anchor
only when the current anchor's `nx` equals the fingerprint of the new key.
Otherwise `ROTATION_UNPROVEN`. This removes trust-on-first-use for the one
operation that otherwise silently resets trust.

### 12.4 Gateway proof of possession

`pop` is an `federation.gateway.pop` envelope whose body is
`{dom, dv, uri, tr}`, signed by a key the registry knows out of band. It
proves the descriptor author controls the key that speaks for that URI.
A descriptor without `pop` is **unproven**, not invalid: registries report it
and strict registries reject it (`GATEWAY_UNPROVEN`). Antares deliberately
does not define a network fetch here; that belongs to a transport binding.

### 12.5 Revocation

Revocation entries are inside the signed descriptor. They are evaluated at
the claimed observation time, not only at "now", so a historical event can
still be judged under the policy in force when it happened.

### 12.6 Routing

`route_query` returns the highest-priority (smallest `pr`) gateway of a known
domain, raising `ROUTE_HOP_LIMIT` when the budget is exhausted and
`ROUTE_LOOP` when the local domain already appears in the visited list.
Antares 2.1 route queries are single-hop resolution; multi-hop path
computation is a transport/profile concern.

## 13. Error codes

| Code | Name | Meaning |
|---|---|---|
| 2000 | POLICY_REJECTED | generic policy/validation rejection |
| 2001 | INTERNAL_ERROR | library-side failure |
| 2002 | CAUSAL_CYCLE | self-parent or cycle |
| 2003 | TOO_MANY_PARENTS | parent count exceeds 8 |
| 2004 | MISSING_SIGNING_KEY | cannot sign |
| 2005 | DESCRIPTOR_EXPIRED | outside validity window |
| 2006 | DESCRIPTOR_VERSION_STALE | version did not increase |
| 2007 | DESCRIPTOR_SIGNATURE_INVALID | anchor or signature failure |
| 2008 | ROUTE_LOOP | local domain already visited |
| 2009 | ROUTE_HOP_LIMIT | hop budget exhausted |
| 2010 | BODY_INVALID | body/envelope shape or type invalid |
| 2011 | UNKNOWN_ALG | algorithm outside the spec |
| 2012 | ALG_UNAVAILABLE | known algorithm, missing provider |
| 2014 | CONE_ROOT_MISMATCH | recomputed cone differs from the claim |
| 2015 | CONE_INCOMPLETE | cone cannot be closed |
| 2016 | CHECKPOINT_SEQ_STALE | checkpoint seq/prev invalid |
| 2017 | SPLIT_VIEW | two checkpoints prove equivocation |
| 2018 | REVOKED_KEY | key revoked at the claimed time |
| 2019 | GATEWAY_UNPROVEN | gateway proof missing/unverifiable |
| 2020 | ROTATION_UNPROVEN | rotation lacks pre-commitment |
| 2021 | WARRANT_STATE_INVALID | illegal warrant transition |
| 2022 | DISCLOSURE_PROOF_INVALID | disclosure proof fails |
| 2023 | BUNDLE_MANIFEST_MISMATCH | bundle hash mismatch |
| 2024 | SEAL_MISMATCH | revealed value != commitment |
| 2025 | TIMESTAMP_UNVERIFIED | token carried but not verified |
| 2026 | DUPLICATE_ENTITY | id present with other content |

## 14. Profiles

A profile fixes the vocabulary Antares deliberately leaves open. 2.1 defines
the container; the judgement stays in the implementation.

**Antares-Causal.** Fixes slot names for `audit.warrant`
(`alternatives`, `constraints`, `observed_state`, `rule_basis`) and requires
`nec` to be `undeclared` unless the profile's judgement function is declared
in `osh`. Consequence: a warrant without a declared function can still be
filed, but cannot claim necessity.

**Antares-Attribution.** Fixes `aud` + `om` conventions for responsibility
outputs and requires an `adjudicate` attestation before a `REJECTED` state is
treated as final.

**Antares-Retention.** Requires, for bundles older than the algorithm's
comfortable horizon: hybrid signatures (`ed25519+ml-dsa-65`), a verified
timestamp token, and at least one cross-anchor from a domain independent of
the producer.

Profiles MUST NOT change the wire format; they constrain field values and
verification policy only.

## 15. Security considerations

- Private keys belong in a KMS/HSM; this library only needs raw values at the
  boundary.
- Descriptor and event signatures authenticate content, not the connection.
  The transport must authenticate the peer.
- Canonical encoding is part of the security contract: re-serialization
  through a non-canonical encoder invalidates verification.
- `ur` means evidence is incomplete. `ok = false` means the supplied evidence
  contradicts itself. The two must never be conflated in a UI.
- Enumeration of anchors and revocations is only as fresh as the descriptor
  version a registry has seen; Antares defines no gossip. Freshness is a
  transport/binding responsibility.
- Gateway proofs bind a key to a URI claim **within the descriptor**; they do
  not prove the endpoint is honest at request time.
- A single-provider algorithm is a retention risk, not just a crypto choice.
  The hybrid path exists so evidence outlives the primitive.
- Timestamp tokens are passthrough unless a verifier is supplied. Never
  present `TIMESTAMP_UNVERIFIED` as verified time.

## 16. Compatibility with 2.0

2.0 is not forward-compatible: the 2.1 envelope adds `k` and `a`, moves `ctx`
into every message, and replaces the 2.0 `ph` payload digest (which hashed
two header fields and therefore committed to nothing) with the evidence root
`er`. Version `2.0` is rejected by a 2.1 verifier rather than reinterpreted.
The changelog records the rationale.

## 17. Conformance and vectors

`CONFORMANCE.md` lists the requirements. `tests/vectors/v2.1.json` pins:

- the canonical CBOR of a reference event (hex),
- the exact signed bytes and signature (hex),
- cone root / size and evidence root,
- a Merkle root with an inclusion proof,
- a salted commitment with a fixed salt,
- an operator-set hash.

An implementation that reproduces those bytes and passes the conformance
suite is conformant for the features it claims.

## 18. Licensing

- Specification text: CC BY 4.0 (`LICENSE-SPEC.md`).
- Reference implementation: Apache License 2.0 (`LICENSE`).
