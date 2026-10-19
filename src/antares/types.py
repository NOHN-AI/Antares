"""Antares type definitions (spec 2.1).

Constants shared by every message family. Transport stays out of scope:
Antares runs over HTTP/3, A2A, MCP, or any authenticated carrier.
"""
from enum import IntEnum

SPEC_VERSION = "2.1"


class ErrorCode(IntEnum):
    """Numeric error codes stable across minor versions."""

    POLICY_REJECTED = 2000            # generic policy/validation rejection
    INTERNAL_ERROR = 2001             # library-side failure
    CAUSAL_CYCLE = 2002               # self-parent or cycle in causal graph
    TOO_MANY_PARENTS = 2003           # parent count exceeds bound
    MISSING_SIGNING_KEY = 2004        # cannot sign without a private key
    DESCRIPTOR_EXPIRED = 2005         # descriptor outside validity window
    DESCRIPTOR_VERSION_STALE = 2006
    DESCRIPTOR_SIGNATURE_INVALID = 2007
    ROUTE_LOOP = 2008                 # local domain already in visited_domains
    ROUTE_HOP_LIMIT = 2009            # max_hops reached 0

    # ── 2.1 additions ──────────────────────────────────────
    BODY_INVALID = 2010               # wire body missing/ill-typed fields
    UNKNOWN_ALG = 2011                # signature algorithm not in the spec
    ALG_UNAVAILABLE = 2012            # algorithm known but provider missing
    CONE_ROOT_MISMATCH = 2014         # recomputed cone root != claimed
    CONE_INCOMPLETE = 2015            # causal cone cannot be closed
    CHECKPOINT_SEQ_STALE = 2016       # checkpoint seq did not increase
    SPLIT_VIEW = 2017                 # two checkpoints, same seq, other root
    REVOKED_KEY = 2018                # key revoked at the claimed time
    GATEWAY_UNPROVEN = 2019           # gateway proof-of-possession missing
    ROTATION_UNPROVEN = 2020          # key rotation lacks pre-commitment
    WARRANT_STATE_INVALID = 2021      # warrant state transition rejected
    DISCLOSURE_PROOF_INVALID = 2022   # disclosure proof does not verify
    BUNDLE_MANIFEST_MISMATCH = 2023   # bundle manifest hash mismatch
    SEAL_MISMATCH = 2024              # revealed value != commitment
    TIMESTAMP_UNVERIFIED = 2025       # timestamp token not independently checked
    DUPLICATE_ENTITY = 2026           # id already present with other content

    @property
    def is_fatal(self) -> bool:
        return self in {
            ErrorCode.CAUSAL_CYCLE,
            ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
            ErrorCode.ROUTE_LOOP,
            ErrorCode.CONE_ROOT_MISMATCH,
            ErrorCode.SPLIT_VIEW,
            ErrorCode.BUNDLE_MANIFEST_MISMATCH,
            ErrorCode.DISCLOSURE_PROOF_INVALID,
            ErrorCode.SEAL_MISMATCH,
        }


# ── message families (domain separation) ───────────────────
MSG_EVENT = "audit.event"
MSG_CHECKPOINT = "audit.checkpoint"
MSG_ANCHOR = "audit.checkpoint.anchor"
MSG_WARRANT = "audit.warrant"
MSG_COUNTER_EVIDENCE = "audit.counter_evidence"
MSG_ATTESTATION = "audit.attestation"
MSG_DESCRIPTOR = "federation.descriptor"
MSG_GATEWAY_POP = "federation.gateway.pop"

SIGNED_MESSAGES = (
    MSG_EVENT,
    MSG_CHECKPOINT,
    MSG_ANCHOR,
    MSG_WARRANT,
    MSG_COUNTER_EVIDENCE,
    MSG_ATTESTATION,
    MSG_DESCRIPTOR,
    MSG_GATEWAY_POP,
)

# ── bounds ─────────────────────────────────────────────────
MAX_PARENT_EVENTS = 8
MAX_ROUTE_HOPS = 8
MAX_CONE_ROOTS = 8
MAX_SLOTS = 32

# ── signature algorithms ───────────────────────────────────
ALG_ED25519 = "ed25519"
ALG_ED25519_MLDSA65 = "ed25519+ml-dsa-65"

SUPPORTED_ALGS = (ALG_ED25519, ALG_ED25519_MLDSA65)

# Component names inside a hybrid signature map.
ALG_COMPONENTS = {
    ALG_ED25519: ("ed25519",),
    ALG_ED25519_MLDSA65: ("ed25519", "ml-dsa-65"),
}
