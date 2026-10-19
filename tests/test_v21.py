"""Antares 2.1 test suite: envelope, cone, checkpoints, warrants,
attestation, selective disclosure, bundles, federation hardening.

Run:
    python -m unittest discover -s tests -v
"""
import copy
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from antares import (
    ALG_ED25519,
    Attestation,
    AttestationError,
    AuditError,
    AuditEvent,
    AuditLog,
    Checkpoint,
    CheckpointError,
    CheckpointStore,
    CounterEvidence,
    DomainDescriptor,
    Envelope,
    EnvelopeError,
    ErrorCode,
    EvidenceSet,
    FederationError,
    FederationRegistry,
    Gateway,
    RevocationEntry,
    SigningError,
    TrustAnchor,
    Warrant,
    WarrantError,
    WarrantLedger,
    build_bundle,
    build_checkpoint,
    commit,
    cone_root_of,
    detect_equivocation,
    encode_deterministic,
    generate_keypair,
    inclusion_proof,
    key_fingerprint,
    key_id_for,
    merkle_root_hex,
    operator_set_hash,
    reveal,
    seal,
    sign_anchor,
    sign_descriptor,
    sign_gateway_pop,
    verify_anchor,
    verify_bundle,
    verify_cone,
    verify_inclusion,
)
from antares.cbor_utils import decode_any
from antares.bundle import MAGIC

DOMAIN = "urn:antares:domain:a"
NODE = "urn:antares:node:a"


def make_event(event_id, parents=None, clock=1, etype="op", rc="ok"):
    return AuditEvent(
        event_id=event_id,
        parent_event_ids=list(parents or []),
        actor_node_id=NODE,
        actor_domain_id=DOMAIN,
        event_type=etype,
        rule_id="r1",
        rule_version="1",
        observed_at="2026-10-19T00:00:00Z",
        logical_clock=clock,
        result_code=rc,
    )


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.kid = key_id_for(NODE)
        self.log = AuditLog(signing_key=self.priv, context_id=b"ctx-1",
                            key_id=self.kid)

    def test_context_is_inside_the_signed_event(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        # A third party verifying from the wire alone must succeed, and the
        # context must be visible in it.
        self.assertEqual(wire["c"], b"ctx-1")
        from antares import verify_wire
        self.assertTrue(verify_wire(wire, self.pub,
                                    expect_msg="audit.event"))

    def test_context_tampering_breaks_signature(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        wire["c"] = b"ctx-2"
        from antares import verify_wire
        self.assertFalse(verify_wire(wire, self.pub))

    def test_key_id_is_signed(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        wire["k"] = "urn:antares:key:mallory"
        from antares import verify_wire
        self.assertFalse(verify_wire(wire, self.pub))

    def test_algorithm_downgrade_rejected(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        wire["a"] = "none"
        from antares import verify_wire
        self.assertFalse(verify_wire(wire, self.pub))

    def test_unknown_wire_key_rejected(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        wire["unsigned_extra"] = 1
        with self.assertRaises(EnvelopeError):
            Envelope.from_wire(wire)

    def test_version_pinned(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        wire["v"] = "2.0"
        with self.assertRaises(EnvelopeError):
            Envelope.from_wire(wire)

    def test_body_must_be_full_form(self):
        event = make_event("e1")
        self.log.add(event)
        wire = event.to_wire()
        del wire["b"]["rc"]
        with self.assertRaises(EnvelopeError):
            AuditEvent.from_wire(wire)

    def test_unknown_algorithm_raises(self):
        with self.assertRaises(SigningError) as ctx:
            generate_keypair("dsa-1024")
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_ALG)


class ConeTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.log = AuditLog(signing_key=self.priv, context_id=b"c",
                            key_id=key_id_for(NODE))

    def build_chain(self):
        self.log.add(make_event("e1"))
        self.log.add(make_event("e2", ["e1"], clock=2))
        self.log.add(make_event("e3", ["e2"], clock=3))
        return [e.to_wire() for e in self.log.list_events()]

    def test_cone_root_independent_of_parent_order(self):
        a = cone_root_of([("e1", "sha256:" + "00" * 32),
                          ("e2", "sha256:" + "11" * 32)])
        b = cone_root_of([("e2", "sha256:" + "11" * 32),
                          ("e1", "sha256:" + "00" * 32)])
        self.assertEqual(a, b)

    def test_cone_commits_to_history(self):
        self.log.add(make_event("e1"))
        self.log.add(make_event("e2", ["e1"], clock=2))
        e1 = self.log.get("e1")
        e2 = self.log.get("e2")
        self.assertNotEqual(e1.cone_root, e2.cone_root)
        self.assertEqual(e2.cone_size, 1)
        self.assertEqual(self.log.get("e3") if False else e2.cone_size, 1)

    def test_verify_cone_complete(self):
        report = verify_cone(self.build_chain())
        self.assertTrue(report["ok"])
        self.assertTrue(report["complete"])
        self.assertEqual(report["events"], 3)

    def test_truncated_history_is_detected(self):
        wires = self.build_chain()
        truncated = [w for w in wires if w["b"]["eid"] != "e1"]
        report = verify_cone(truncated)
        self.assertFalse(report["ok"])
        self.assertIn("e2", report["undeclared_missing_parents"])

    def test_declared_missing_parent_is_incomplete_not_false(self):
        ev = make_event("orphan", ["never-seen"])
        self.log.add(ev)
        report = verify_cone([ev.to_wire()])
        self.assertTrue(report["ok"])
        self.assertFalse(report["complete"])
        self.assertIn("orphan", report["unverifiable"])

    def test_forged_cone_root_detected(self):
        wires = self.build_chain()
        forged = copy.deepcopy(wires)
        for wire in forged:
            if wire["b"]["eid"] == "e2":
                wire["b"]["cr"] = "sha256:" + "ab" * 32
        report = verify_cone(forged)
        self.assertFalse(report["ok"])
        self.assertIn("e2", report["cone_root_mismatch"])

    def test_duplicate_id_with_other_content_rejected(self):
        wires = self.build_chain()
        forged = copy.deepcopy(wires[0])
        forged["b"]["rc"] = "tampered"
        with self.assertRaises(AuditError):
            verify_cone([wires[0], forged])


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.kid = key_id_for(DOMAIN)
        self.log = AuditLog(signing_key=self.priv, context_id=b"c",
                            key_id=key_id_for(NODE))
        self.log.add(make_event("e1"))
        self.log.add(make_event("e2", ["e1"], clock=2))

    def test_checkpoint_signs_and_verifies(self):
        cp = build_checkpoint(domain_id=DOMAIN,
                              events=self.log.wire_list(), seq=1,
                              private_key=self.priv, key_id=self.kid)
        self.assertTrue(cp.verify(self.pub))
        self.assertEqual(cp.size, 2)

    def test_checkpoint_root_is_order_independent(self):
        wires = self.log.wire_list()
        a = build_checkpoint(domain_id=DOMAIN, events=wires, seq=1,
                             private_key=self.priv, key_id=self.kid)
        b = build_checkpoint(domain_id=DOMAIN, events=list(reversed(wires)),
                             seq=1, private_key=self.priv, key_id=self.kid)
        self.assertEqual(a.root, b.root)

    def test_reordered_wire_roundtrip(self):
        cp = build_checkpoint(domain_id=DOMAIN, events=self.log.wire_list(),
                              seq=1, private_key=self.priv, key_id=self.kid)
        again = Checkpoint.from_wire(cp.to_wire())
        self.assertEqual(again.root, cp.root)
        self.assertTrue(again.verify(self.pub))

    def test_equivocation_detected(self):
        other = AuditLog(signing_key=self.priv, context_id=b"c",
                         key_id=key_id_for(NODE))
        other.add(make_event("e9"))
        a = build_checkpoint(domain_id=DOMAIN, events=self.log.wire_list(),
                             seq=1, private_key=self.priv, key_id=self.kid)
        b = build_checkpoint(domain_id=DOMAIN, events=other.wire_list(),
                             seq=1, private_key=self.priv, key_id=self.kid)
        self.assertTrue(detect_equivocation(a, b))
        store = CheckpointStore()
        store.add(a)
        with self.assertRaises(CheckpointError) as ctx:
            store.add(b)
        self.assertEqual(ctx.exception.code, ErrorCode.SPLIT_VIEW)

    def test_chain_linkage(self):
        first = build_checkpoint(domain_id=DOMAIN,
                                 events=self.log.wire_list(), seq=1,
                                 private_key=self.priv, key_id=self.kid)
        store = CheckpointStore()
        store.add(first)
        second = build_checkpoint(domain_id=DOMAIN,
                                  events=self.log.wire_list(), seq=2,
                                  private_key=self.priv, key_id=self.kid,
                                  prev=store.head_hash(DOMAIN))
        store.add(second)
        self.assertEqual(len(store.chain(DOMAIN)), 2)

    def test_cross_anchor(self):
        cp = build_checkpoint(domain_id=DOMAIN, events=self.log.wire_list(),
                              seq=1, private_key=self.priv, key_id=self.kid)
        anchor = sign_anchor(cp, by_domain="urn:antares:domain:b",
                             private_key=self.priv, key_id=self.kid)
        self.assertTrue(verify_anchor(anchor, self.pub, target=cp))
        cp2 = build_checkpoint(domain_id=DOMAIN, events=self.log.wire_list(),
                               seq=2, private_key=self.priv, key_id=self.kid)
        self.assertFalse(verify_anchor(anchor, self.pub, target=cp2))


class WarrantTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.kid = key_id_for(DOMAIN)

    def warrant(self, wid, sup=""):
        return Warrant(
            warrant_id=wid,
            target_cone_root="sha256:" + "11" * 32,
            target_size=3,
            decision_event_id="e3",
            necessity="necessary",
            rule_id="policy.ap",
            rule_version="1.2",
            constraint_set_hash="cmt:" + "22" * 32,
            slots={"evidence": "cmt:" + "33" * 32},
            supersedes=sup,
            asserted_at="2026-10-19T00:00:00Z",
        ).sign(self.priv, self.kid)

    def counter(self, cid, wid):
        return CounterEvidence(
            counter_id=cid,
            warrant_id=wid,
            counter_cone_root="sha256:" + "44" * 32,
            counter_size=2,
            slot="evidence",
            kind="evidence",
            expected="cmt:" + "33" * 32,
            actual="cmt:" + "55" * 32,
        ).sign(self.priv, self.kid)

    def test_lifecycle(self):
        ledger = WarrantLedger()
        w = self.warrant("w1")
        ledger.add_warrant(w)
        self.assertEqual(ledger.state_of("w1"), "ASSERTED")

        c = self.counter("c1", "w1")
        ledger.add_counter(c)
        self.assertEqual(ledger.state_of("w1"), "CHALLENGED")
        self.assertEqual(ledger.counter_state("c1"), "ASSERTED")

        ledger.add_warrant(self.warrant("w2", sup="c1"))
        self.assertEqual(ledger.counter_state("c1"), "REBUTTED")
        self.assertEqual(ledger.state_of("w1"), "REBUTTED")

    def test_upheld_challenge_rejects_claim(self):
        ledger = WarrantLedger()
        ledger.add_warrant(self.warrant("w1"))
        ledger.add_counter(self.counter("c1", "w1"))
        ledger.add_adjudication("c1", "upheld")
        self.assertEqual(ledger.counter_state("c1"), "UPHELD")
        self.assertEqual(ledger.state_of("w1"), "REJECTED")

    def test_dismissed_challenge_leaves_claim_standing(self):
        ledger = WarrantLedger()
        ledger.add_warrant(self.warrant("w1"))
        ledger.add_counter(self.counter("c1", "w1"))
        ledger.add_adjudication("c1", "dismissed")
        self.assertEqual(ledger.state_of("w1"), "REBUTTED")

    def test_unknown_warrant_rejected(self):
        ledger = WarrantLedger()
        with self.assertRaises(WarrantError):
            ledger.add_counter(self.counter("c1", "nope"))

    def test_warrant_roundtrip_and_tamper(self):
        w = self.warrant("w1")
        again = Warrant.from_wire(w.to_wire())
        self.assertTrue(again.verify(self.pub))
        wire = w.to_wire()
        wire["b"]["nec"] = "sufficient"
        self.assertFalse(Warrant.from_wire(wire).verify(self.pub))


class AttestationTests(unittest.TestCase):
    MANIFEST = [
        {"n": "NS", "l": "T0", "i": 0},
        {"n": "BFC", "l": "T1", "i": 1},
        {"n": "ACC", "l": "T2", "i": 2},
    ]

    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.kid = key_id_for(DOMAIN)

    def attestation(self):
        return Attestation(
            attestation_id="a1",
            target_cone_root="sha256:" + "66" * 32,
            target_size=4,
            kind="audit",
            auditor_domain=DOMAIN,
            operator_manifest=list(self.MANIFEST),
            verdict="block",
            findings_root="sha256:" + "77" * 32,
            issued_at="2026-10-19T00:00:00Z",
        ).sign(self.priv, self.kid)

    def test_operator_set_hash_is_pinned(self):
        self.assertEqual(operator_set_hash(self.MANIFEST),
                         self.attestation().operator_set_hash)

    def test_order_changes_the_hash(self):
        reordered = [self.MANIFEST[1], self.MANIFEST[0], self.MANIFEST[2]]
        self.assertNotEqual(operator_set_hash(self.MANIFEST),
                            operator_set_hash(reordered))

    def test_manifest_tamper_rejected(self):
        wire = self.attestation().to_wire()
        wire["b"]["om"] = [{"n": "ACC", "l": "T2", "i": 2}]
        with self.assertRaises(AttestationError):
            Attestation.from_wire(wire)

    def test_attestation_becomes_an_auditable_event(self):
        att = self.attestation()
        log = AuditLog(signing_key=self.priv, context_id=b"c",
                       key_id=self.kid)
        log.add(att.to_event(actor_node_id=NODE))
        event = log.get("a1")
        self.assertEqual(event.result_code, "block")
        self.assertEqual(event.ext["osh"], att.operator_set_hash)
        self.assertTrue(log.verify_signature(event, self.pub))
        self.assertEqual(event.evidence_root, att.target_cone_root)


class DisclosureTests(unittest.TestCase):
    def test_seal_and_reveal(self):
        cmt, salt = seal({"payload": "secret"})
        self.assertTrue(reveal(cmt, salt, {"payload": "secret"}))
        self.assertFalse(reveal(cmt, salt, {"payload": "other"}))

    def test_commitment_is_salted(self):
        a = commit({"x": 1}, b"0" * 16)
        b = commit({"x": 1}, b"1" * 16)
        self.assertNotEqual(a, b)

    def test_short_salt_rejected(self):
        with self.assertRaises(Exception):
            commit({"x": 1}, b"tiny")

    def test_selective_disclosure(self):
        evidence = EvidenceSet()
        for index in range(6):
            evidence.add(f"chunk-{index}".encode())
        subset = evidence.disclose([1, 4])
        self.assertTrue(EvidenceSet.verify_disclosure(subset))
        self.assertEqual(len(subset["items"]), 2)

    def test_disclosure_tamper_detected(self):
        evidence = EvidenceSet()
        for index in range(4):
            evidence.add(f"blob-{index}".encode())
        subset = evidence.disclose([2])
        subset["items"][0]["data"] = b"forged"
        self.assertFalse(EvidenceSet.verify_disclosure(subset))

    def test_full_evidence_matches_root(self):
        evidence = EvidenceSet()
        for index in range(5):
            evidence.add(f"v{index}".encode())
        items = [{"cmt": c, "salt": s, "data": d}
                 for s, d, c in evidence.items()]
        self.assertTrue(EvidenceSet.verify_full(items, evidence.root()))


class MerkleTests(unittest.TestCase):
    def test_inclusion_proofs_all_sizes(self):
        for size in range(1, 10):
            leaves = [f"leaf-{i}".encode() for i in range(size)]
            root = bytes.fromhex(merkle_root_hex(leaves)[7:])
            for index in range(size):
                proof = inclusion_proof(leaves, index)
                self.assertTrue(verify_inclusion(leaves[index], index, size,
                                                 proof, root),
                                f"size={size} index={index}")

    def test_wrong_index_rejected(self):
        leaves = [f"leaf-{i}".encode() for i in range(5)]
        root = bytes.fromhex(merkle_root_hex(leaves)[7:])
        proof = inclusion_proof(leaves, 0)
        self.assertFalse(verify_inclusion(leaves[1], 1, 5, proof, root))

    def test_odd_tree_has_no_duplicate_ambiguity(self):
        three = [b"a", b"b", b"c"]
        four = [b"a", b"b", b"c", b"c"]
        self.assertNotEqual(merkle_root_hex(three), merkle_root_hex(four))


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.kid = key_id_for(NODE)
        self.log = AuditLog(signing_key=self.priv, context_id=b"c",
                            key_id=self.kid)
        self.log.add(make_event("e1"))
        self.log.add(make_event("e2", ["e1"], clock=2))
        self.evidence = EvidenceSet()
        self.evidence.add(b"invoice-42")
        self.evidence.add(b"chat-log")
        self.keys = {self.kid: self.pub}

    def build(self):
        att = Attestation(
            attestation_id="a1",
            target_cone_root=self.log.get("e2").cone_root,
            target_size=2,
            kind="audit",
            auditor_domain=DOMAIN,
            operator_manifest=[{"n": "ACC", "l": "T2", "i": 0}],
            verdict="pass",
            findings_root="sha256:" + "88" * 32,
            issued_at="2026-10-19T00:00:00Z",
        ).sign(self.priv, self.kid)
        return build_bundle(
            events=self.log.wire_list(),
            attestations=[att],
            evidence=self.evidence,
            disclosures=[self.evidence.disclose([0])],
            timestamps=[{"target": "sha256:" + "99" * 32,
                         "kind": "rfc3161", "token": b"fake-token"}],
        )

    def test_bundle_roundtrip_verifies(self):
        report = verify_bundle(self.build(), self.keys)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["events"], 2)
        self.assertEqual(report["attestations"], 1)
        self.assertTrue(report["cone"]["complete"])
        # A token we cannot independently check must be surfaced, not ignored.
        codes = [w["code"] for w in report["warnings"]]
        self.assertIn(int(ErrorCode.TIMESTAMP_UNVERIFIED), codes)

    def test_content_edit_breaks_manifest(self):
        data = self.build()
        payload = decode_any(data[len(MAGIC):])
        payload["events"][0]["b"]["rc"] = "tampered"
        forged = MAGIC + encode_deterministic(payload)
        report = verify_bundle(forged, self.keys)
        self.assertFalse(report["ok"])
        self.assertIn(int(ErrorCode.BUNDLE_MANIFEST_MISMATCH),
                      [e["code"] for e in report["errors"]])

    def test_unknown_key_is_an_error_when_required(self):
        report = verify_bundle(self.build(), {}, require_keys=True)
        self.assertFalse(report["ok"])
        report = verify_bundle(self.build(), {}, require_keys=False)
        self.assertTrue(report["ok"])
        self.assertTrue(report["warnings"])

    def test_missing_magic_rejected(self):
        report = verify_bundle(b"not-a-bundle", {})
        self.assertFalse(report["ok"])


class FederationHardeningTests(unittest.TestCase):
    def setUp(self):
        self.old_priv, self.old_pub = generate_keypair()
        self.new_priv, self.new_pub = generate_keypair()
        self.domain = "urn:antares:domain:remote"
        self.old_kid = key_id_for(self.domain)
        self.new_kid = key_id_for(self.domain) + ":v2"
        self.reg = FederationRegistry("urn:antares:domain:local")

    def descriptor(self, private_key, kid, version=1, revocations=None):
        now = time.time()
        return sign_descriptor(
            DomainDescriptor(
                domain_id=self.domain,
                descriptor_version=version,
                valid_from=now - 60,
                valid_until=now + 3600,
                gateways=[Gateway("http3://gw.example:443", "http3", 10,
                                  ["audit"])],
                services=["urn:antares:service:routing"],
                trust_anchors=[TrustAnchor(kid, "ed25519",
                                           self.new_pub
                                           if kid == self.new_kid
                                           else self.old_pub)],
                revocations=list(revocations or []),
            ),
            private_key,
            key_id=kid,
        )

    def test_rotation_requires_pre_commitment(self):
        self.reg.add_trust_anchor(self.domain, self.old_pub,
                                  key_id=self.old_kid)
        with self.assertRaises(FederationError) as ctx:
            self.reg.register(self.descriptor(self.new_priv, self.new_kid))
        self.assertEqual(ctx.exception.code, ErrorCode.ROTATION_UNPROVEN)

    def test_rotation_with_pre_commitment_succeeds(self):
        self.reg.add_trust_anchor(
            self.domain, self.old_pub, key_id=self.old_kid,
            next_key_hash=key_fingerprint(self.new_pub),
        )
        self.reg.register(self.descriptor(self.new_priv, self.new_kid))
        self.assertEqual(self.reg.anchor(self.domain).key_id, self.new_kid)
        self.assertIn("rotated", " ".join(self.reg.warnings(self.domain)))

    def test_revoked_signing_key_rejected(self):
        self.reg.add_trust_anchor(self.domain, self.old_pub,
                                  key_id=self.old_kid)
        desc = self.descriptor(
            self.old_priv, self.old_kid, version=1,
            revocations=[RevocationEntry(self.old_kid, time.time() - 10,
                                         "compromised")],
        )
        with self.assertRaises(FederationError) as ctx:
            self.reg.register(desc)
        self.assertEqual(ctx.exception.code, ErrorCode.REVOKED_KEY)

    def test_verify_event_after_anchor(self):
        self.reg.add_trust_anchor(self.domain, self.old_pub,
                                  key_id=self.old_kid)
        self.reg.register(self.descriptor(self.old_priv, self.old_kid))
        log = AuditLog(signing_key=self.old_priv, context_id=b"c",
                       key_id=self.old_kid, domain_id=self.domain)
        event = make_event("e1")
        event.actor_domain_id = self.domain
        event.actor_node_id = "urn:antares:node:remote"
        log.add(event)
        self.assertTrue(self.reg.verify_event(event))
        event.actor_domain_id = "urn:antares:domain:evil"
        self.assertFalse(self.reg.verify_event(event))

    def test_gateway_proof_of_possession(self):
        gw_priv, gw_pub = generate_keypair()
        gw_kid = "urn:antares:key:gw"
        now = time.time()
        gateway = Gateway("http3://gw.example:443", "http3", 10, ["audit"])
        sign_gateway_pop(gateway, domain_id=self.domain,
                         descriptor_version=1, private_key=gw_priv,
                         key_id=gw_kid)
        desc = sign_descriptor(
            DomainDescriptor(
                domain_id=self.domain,
                descriptor_version=1,
                valid_from=now - 60,
                valid_until=now + 3600,
                gateways=[gateway],
                trust_anchors=[TrustAnchor(self.old_kid, "ed25519",
                                           self.old_pub)],
            ),
            self.old_priv,
            key_id=self.old_kid,
        )
        self.reg.add_trust_anchor(self.domain, self.old_pub,
                                  key_id=self.old_kid)
        self.reg.register(desc, gateway_keys={gw_kid: gw_pub},
                          require_pop=True)
        self.assertEqual(self.reg.count(), 1)

    def test_unproven_gateway_rejected_in_strict_mode(self):
        self.reg.add_trust_anchor(self.domain, self.old_pub,
                                  key_id=self.old_kid)
        with self.assertRaises(FederationError) as ctx:
            self.reg.register(self.descriptor(self.old_priv, self.old_kid),
                              require_pop=True)
        self.assertEqual(ctx.exception.code, ErrorCode.GATEWAY_UNPROVEN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
