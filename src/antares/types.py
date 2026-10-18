"""Antares type definitions.
Constants for the audit and federation message layer. Transport is out of
scope: Antares runs over HTTP/3, A2A, MCP, or any authenticated carrier.
"""
from enum import IntEnum

SPEC_VERSION = "2.0"


class ErrorCode(IntEnum):
    """Numeric error codes stable across minor versions."""

    POLICY_REJECTED = 2000       # generic policy/validation rejection
    INTERNAL_ERROR = 2001        # library-side failure
    CAUSAL_CYCLE = 2002          # self-parent or cycle in causal graph
    TOO_MANY_PARENTS = 2003      # parent count exceeds bound
    MISSING_SIGNING_KEY = 2004   # cannot sign without a private key
    DESCRIPTOR_EXPIRED = 2005    # domain descriptor outside validity window
    DESCRIPTOR_VERSION_STALE = 2006
    DESCRIPTOR_SIGNATURE_INVALID = 2007
    ROUTE_LOOP = 2008            # local domain already in visited_domains
    ROUTE_HOP_LIMIT = 2009       # max_hops reached 0

    @property
    def is_fatal(self) -> bool:
        return self in {
            ErrorCode.CAUSAL_CYCLE,
            ErrorCode.DESCRIPTOR_SIGNATURE_INVALID,
            ErrorCode.ROUTE_LOOP,
        }


# Bounds
MAX_PARENT_EVENTS = 8
MAX_ROUTE_HOPS = 8

# Signature algorithms
ALG_ED25519 = "ed25519"
