"""Antares core test suite.

Run:
    python -m unittest discover -s tests
or:
    python tests/test_core.py
"""
import sys
import os
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from antares import (
    AuditLog,
    AuditEvent,
    AuditError,
    ErrorCode,
    FederationRegistry,
    DomainDescriptor,
    Gateway,
    TrustAnchor,
    FederationError,
    generate_keypair,
    sign_descriptor,
    state_hash,
    SimpleKVStore,
    MAX_PARENT_EVENTS,
)


def make_event(event_id, parents=None, clock=1):
    return AuditEvent(
        event_id=event_id,
        parent_event_ids=list(parents or []),
        actor_node_id="urn:antares:node:a",
        actor_domain_id="urn:antares:domain:a",
        event_type="op",
        rule_id="r1",
        rule_version="1",
        observed_at="2026-10-18T00:00:00Z",
        logical_clock=clock,
    )


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.log = AuditLog(signing_key=self.priv, context_id=b"ctx-1")

    def test_sign_and_verify(self):
        ev = make_event("e1")
        self.log.add(ev)
        self.assertTrue(ev.signature)
        self.assertTrue(self.log.verify_signature(ev, self.pub))

    def test_self_parent_rejected(self):
        ev = make_event("e1", parents=["e1"])
        with self.assertRaises(AuditError) as ctx:
            self.log.add(ev)
        self.assertEqual(ctx.exception.code, ErrorCode.CAUSAL_CYCLE)

    def test_known_cycle_rejected(self):
        # New event e2 with parent e1. If e1's descendant set already contains
        # e2, adding e2 -> e1 closes the cycle e2 -> e1 -> e2.
        self.log.add(make_event("e1"))
        self.log._children.setdefault("e1", set()).add("e2")
        with self.assertRaises(AuditError) as ctx:
            self.log.add(make_event("e2", parents=["e1"]))
        self.assertEqual(ctx.exception.code, ErrorCode.CAUSAL_CYCLE)

    def test_too_many_parents(self):
        ev = make_event(
            "e1",
            parents=[f"p{i}" for i in range(MAX_PARENT_EVENTS + 1)],
        )
        with self.assertRaises(AuditError) as ctx:
            self.log.add(ev)
        self.assertEqual(ctx.exception.code, ErrorCode.TOO_MANY_PARENTS)

    def test_missing_parents_marked_unresolved(self):
        ev = make_event("e1", parents=["missing-1", "missing-2"])
        self.log.add(ev)
        self.assertEqual(
            set(ev.unresolved_parents), {"missing-1", "missing-2"}
        )

    def test_tampered_signature_fails(self):
        ev = make_event("e1")
        self.log.add(ev)
        ev.result_code = "TAMPERED"
        self.assertFalse(self.log.verify_signature(ev, self.pub))

    def test_state_hash_changes_with_state(self):
        h1 = state_hash({"x": 1})
        h2 = state_hash({"x": 2})
        self.assertNotEqual(h1, h2)
        self.assertTrue(h1.startswith("sha256:"))


class FederationTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.domain = "urn:antares:domain:remote"
        self.reg = FederationRegistry("urn:antares:domain:local")
        self.reg.add_trust_anchor(self.domain, self.pub)

    def make_descriptor(self, version=1, ttl=3600):
        now = time.time()
        desc = DomainDescriptor(
            domain_id=self.domain,
            descriptor_version=version,
            valid_from=now - 60,
            valid_until=now + ttl,
            gateways=[
                Gateway(
                    uri="http3://gw.example:443",
                    transport="http3",
                    priority=10,
                    profiles=["audit"],
                )
            ],
            services=["urn:antares:service:routing"],
            trust_anchors=[
                TrustAnchor(
                    key_id="k1",
                    algorithm="ed25519",
                    public_key=self.pub,
                )
            ],
        )
        return sign_descriptor(desc, self.priv)

    def test_descriptor_sign_and_register(self):
        desc = self.make_descriptor()
        self.reg.register(desc)
        self.assertEqual(self.reg.count(), 1)

    def test_expired_descriptor_rejected(self):
        desc = self.make_descriptor(ttl=-100)
        with self.assertRaises(FederationError) as ctx:
            self.reg.register(desc)
        self.assertEqual(ctx.exception.code, ErrorCode.DESCRIPTOR_EXPIRED)

    def test_version_must_increase(self):
        self.reg.register(self.make_descriptor(version=2))
        with self.assertRaises(FederationError) as ctx:
            self.reg.register(self.make_descriptor(version=2))
        self.assertEqual(
            ctx.exception.code, ErrorCode.DESCRIPTOR_VERSION_STALE
        )

    def test_unsigned_descriptor_rejected(self):
        desc = self.make_descriptor()
        desc.signature = "00" * 64
        with self.assertRaises(FederationError) as ctx:
            self.reg.register(desc)
        self.assertEqual(
            ctx.exception.code, ErrorCode.DESCRIPTOR_SIGNATURE_INVALID
        )

    def test_route_resolved(self):
        self.reg.register(self.make_descriptor())
        out = self.reg.route_query(
            target_domain=self.domain,
            visited_domains=["urn:antares:domain:other"],
            max_hops=4,
        )
        self.assertEqual(out["status"], "resolved")
        self.assertEqual(out["next_hop"], "http3://gw.example:443")

    def test_route_loop(self):
        self.reg.register(self.make_descriptor())
        with self.assertRaises(FederationError) as ctx:
            self.reg.route_query(
                target_domain=self.domain,
                visited_domains=["urn:antares:domain:local"],
                max_hops=4,
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ROUTE_LOOP)

    def test_route_hop_limit(self):
        self.reg.register(self.make_descriptor())
        with self.assertRaises(FederationError) as ctx:
            self.reg.route_query(
                target_domain=self.domain,
                visited_domains=[],
                max_hops=0,
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ROUTE_HOP_LIMIT)


class BusinessHandlerTests(unittest.TestCase):
    def test_deterministic_kv(self):
        store = SimpleKVStore()
        state, result = store.execute(
            "inventory.reserve",
            b'{"item": "widget", "qty": 3}',
            {},
        )
        self.assertEqual(result["total"], 3)
        state, result = store.execute(
            "inventory.reserve",
            b'{"item": "widget", "qty": 2}',
            state,
        )
        self.assertEqual(result["total"], 5)
        self.assertEqual(state_hash(state), state_hash(state))


if __name__ == "__main__":
    unittest.main(verbosity=2)
