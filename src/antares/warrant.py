"""Rebuttable claims (spec §9) — evidence slots only, no algorithm.

The protocol does **not** define what makes a decision necessary. It defines
where that argument is written down, how it is challenged, and how the result
is recorded, so a third party can replay the argument without trusting either
party.

  Warrant        "decision D was justified; here are the slots and their
                  commitments"
  CounterEvidence "slot X does not hold; here is the contradicting cone"
  Rebuttal       another Warrant whose `sup` names the counter-evidence
  Adjudication   an Attestation with kind=adjudicate naming the counter

States are derived from the message set, never stored as mutable flags, so
ingest order cannot change the outcome.
"""
from dataclasses import dataclass, field

from .envelope import Envelope, EnvelopeError
from .types import ALG_ED25519, ErrorCode, MSG_COUNTER_EVIDENCE, MSG_WARRANT

WARRANT_KEYS = ("wid", "tar", "tsz", "dec", "nec", "rid", "rv",
                "csh", "sl", "sup", "at")
COUNTER_KEYS = ("cid", "wid", "tar", "tsz", "sol", "kind", "exp",
                "act", "note")

NECESSITY_SLOTS = (
    "undeclared",
    "necessary",
    "sufficient",
    "necessary_and_sufficient",
)
COUNTER_KINDS = ("state", "evidence", "rule", "timestamp")

WARRANT_STATES = ("ASSERTED", "CHALLENGED", "REBUTTED", "REJECTED")
COUNTER_STATES = ("ASSERTED", "REBUTTED", "UPHELD", "DISMISSED")


class WarrantError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass
class Warrant:
    warrant_id: str
    target_cone_root: str
    target_size: int = 0
    decision_event_id: str = ""
    necessity: str = "undeclared"
    rule_id: str = ""
    rule_version: str = ""
    constraint_set_hash: str = ""
    slots: dict = field(default_factory=dict)
    supersedes: str = ""
    asserted_at: str = ""
    key_id: str = ""
    alg: str = ALG_ED25519
    ctx: bytes = b""
    signature: str = ""

    def to_body(self) -> dict:
        return {
            "wid": self.warrant_id,
            "tar": self.target_cone_root,
            "tsz": int(self.target_size),
            "dec": self.decision_event_id,
            "nec": self.necessity,
            "rid": self.rule_id,
            "rv": self.rule_version,
            "csh": self.constraint_set_hash,
            "sl": dict(self.slots),
            "sup": self.supersedes,
            "at": self.asserted_at,
        }

    def to_envelope(self) -> Envelope:
        return Envelope(
            msg=MSG_WARRANT,
            body=self.to_body(),
            ctx=self.ctx,
            key_id=self.key_id,
            alg=self.alg,
            signature=self.signature,
        )

    def to_wire(self) -> dict:
        return self.to_envelope().to_wire()

    def sign(self, private_key, key_id: str = "") -> "Warrant":
        env = self.to_envelope()
        env.sign(private_key, key_id=key_id)
        self.key_id, self.alg, self.signature = env.key_id, env.alg, env.signature
        return self

    def verify(self, public_key) -> bool:
        return self.to_envelope().verify(public_key, expect_msg=MSG_WARRANT)

    @classmethod
    def from_wire(cls, wire: dict) -> "Warrant":
        env = Envelope.from_wire(wire)
        if env.msg != MSG_WARRANT:
            raise WarrantError(ErrorCode.BODY_INVALID,
                               f"expected {MSG_WARRANT}")
        body = env.body
        if set(body) != set(WARRANT_KEYS):
            raise WarrantError(ErrorCode.BODY_INVALID,
                               "warrant body key set invalid")
        if body["nec"] not in NECESSITY_SLOTS:
            raise WarrantError(ErrorCode.BODY_INVALID,
                               f"unknown necessity slot {body['nec']!r}")
        return cls(
            warrant_id=body["wid"],
            target_cone_root=body["tar"],
            target_size=body["tsz"],
            decision_event_id=body["dec"],
            necessity=body["nec"],
            rule_id=body["rid"],
            rule_version=body["rv"],
            constraint_set_hash=body["csh"],
            slots=dict(body["sl"]),
            supersedes=body["sup"],
            asserted_at=body["at"],
            key_id=env.key_id,
            alg=env.alg,
            ctx=env.ctx,
            signature=env.signature,
        )


@dataclass
class CounterEvidence:
    counter_id: str
    warrant_id: str
    counter_cone_root: str
    counter_size: int = 0
    slot: str = ""
    kind: str = "state"
    expected: str = ""
    actual: str = ""
    note_hash: str = ""
    key_id: str = ""
    alg: str = ALG_ED25519
    ctx: bytes = b""
    signature: str = ""

    def to_body(self) -> dict:
        return {
            "cid": self.counter_id,
            "wid": self.warrant_id,
            "tar": self.counter_cone_root,
            "tsz": int(self.counter_size),
            "sol": self.slot,
            "kind": self.kind,
            "exp": self.expected,
            "act": self.actual,
            "note": self.note_hash,
        }

    def to_envelope(self) -> Envelope:
        return Envelope(
            msg=MSG_COUNTER_EVIDENCE,
            body=self.to_body(),
            ctx=self.ctx,
            key_id=self.key_id,
            alg=self.alg,
            signature=self.signature,
        )

    def to_wire(self) -> dict:
        return self.to_envelope().to_wire()

    def sign(self, private_key, key_id: str = "") -> "CounterEvidence":
        env = self.to_envelope()
        env.sign(private_key, key_id=key_id)
        self.key_id, self.alg, self.signature = env.key_id, env.alg, env.signature
        return self

    def verify(self, public_key) -> bool:
        return self.to_envelope().verify(
            public_key, expect_msg=MSG_COUNTER_EVIDENCE
        )

    @classmethod
    def from_wire(cls, wire: dict) -> "CounterEvidence":
        env = Envelope.from_wire(wire)
        if env.msg != MSG_COUNTER_EVIDENCE:
            raise WarrantError(ErrorCode.BODY_INVALID,
                               f"expected {MSG_COUNTER_EVIDENCE}")
        body = env.body
        if set(body) != set(COUNTER_KEYS):
            raise WarrantError(ErrorCode.BODY_INVALID,
                               "counter-evidence body key set invalid")
        if body["kind"] not in COUNTER_KINDS:
            raise WarrantError(ErrorCode.BODY_INVALID,
                               f"unknown counter kind {body['kind']!r}")
        return cls(
            counter_id=body["cid"],
            warrant_id=body["wid"],
            counter_cone_root=body["tar"],
            counter_size=body["tsz"],
            slot=body["sol"],
            kind=body["kind"],
            expected=body["exp"],
            actual=body["act"],
            note_hash=body["note"],
            key_id=env.key_id,
            alg=env.alg,
            ctx=env.ctx,
            signature=env.signature,
        )


class WarrantLedger:
    """Deterministic state derived from a set of warrant messages.

    `state_of(wid)` does not depend on ingest order; it is recomputed from
    the stored set. Conflicts that the protocol cannot resolve resolve to
    CHALLENGED / UNDECIDED — never to a silent winner.
    """

    def __init__(self):
        self._warrants: dict = {}
        self._counters: dict = {}
        self._rebuttals: dict = {}   # warrant id -> counter id it answers
        self._adjudications: dict = {}  # counter id -> "upheld" | "dismissed"

    # ── ingest ─────────────────────────────────────────────
    def add_warrant(self, warrant: Warrant) -> None:
        if warrant.supersedes:
            if warrant.supersedes not in self._counters:
                raise WarrantError(
                    ErrorCode.WARRANT_STATE_INVALID,
                    "rebuttal names an unknown counter-evidence",
                )
            self._rebuttals[warrant.warrant_id] = warrant.supersedes
        prior = self._warrants.get(warrant.warrant_id)
        if prior is not None and prior.signature != warrant.signature:
            raise WarrantError(ErrorCode.DUPLICATE_ENTITY,
                               f"warrant {warrant.warrant_id} conflicts")
        self._warrants[warrant.warrant_id] = warrant

    def add_counter(self, counter: CounterEvidence) -> None:
        if counter.warrant_id not in self._warrants:
            raise WarrantError(ErrorCode.WARRANT_STATE_INVALID,
                               "counter-evidence names an unknown warrant")
        if counter.kind not in COUNTER_KINDS:
            raise WarrantError(ErrorCode.BODY_INVALID,
                               f"unknown counter kind {counter.kind!r}")
        prior = self._counters.get(counter.counter_id)
        if prior is not None and prior.signature != counter.signature:
            raise WarrantError(ErrorCode.DUPLICATE_ENTITY,
                               f"counter {counter.counter_id} conflicts")
        self._counters[counter.counter_id] = counter

    def add_adjudication(self, counter_id: str, verdict: str) -> None:
        if counter_id not in self._counters:
            raise WarrantError(ErrorCode.WARRANT_STATE_INVALID,
                               "adjudication names an unknown counter")
        if verdict not in ("upheld", "dismissed"):
            raise WarrantError(ErrorCode.WARRANT_STATE_INVALID,
                               f"unknown verdict {verdict!r}")
        self._adjudications[counter_id] = verdict

    # ── derived state ──────────────────────────────────────
    def state_of(self, warrant_id: str) -> str:
        warrant = self._warrants.get(warrant_id)
        if warrant is None:
            raise WarrantError(ErrorCode.WARRANT_STATE_INVALID,
                               f"unknown warrant {warrant_id}")
        counters = [c for c in self._counters.values()
                    if c.warrant_id == warrant_id]
        if not counters:
            return "REBUTTED" if warrant.supersedes else "ASSERTED"
        states = [self.counter_state(c.counter_id) for c in counters]
        if "UPHELD" in states:
            return "REJECTED"
        if all(s in ("REBUTTED", "DISMISSED") for s in states):
            return "REBUTTED"
        return "CHALLENGED"

    def counter_state(self, counter_id: str) -> str:
        verdict = self._adjudications.get(counter_id)
        if verdict == "upheld":
            return "UPHELD"
        if verdict == "dismissed":
            return "DISMISSED"
        if counter_id in self._rebuttals.values():
            return "REBUTTED"
        return "ASSERTED"

    # ── queries ────────────────────────────────────────────
    def warrants(self) -> list:
        return [self._warrants[k] for k in sorted(self._warrants)]

    def counters(self) -> list:
        return [self._counters[k] for k in sorted(self._counters)]

    def snapshot(self) -> dict:
        return {
            "warrants": {
                wid: self.state_of(wid) for wid in sorted(self._warrants)
            },
            "counters": {
                cid: self.counter_state(cid)
                for cid in sorted(self._counters)
            },
        }
