# Changelog — v2.0

## 2.0 — Redefinition as audit and federation layer

### Removed

The previous "GFSIP" transport protocol shell duplicated functionality
already provided by QUIC, TLS, and HTTP/2, and is removed:

- Frame header and all frame types (DATA, OPEN, ACK, RST, CLOSE, GOAWAY).
- Session state machine, handshake, and session resumption.
- Channels and per-stream multiplexing.
- ACK/deduplication, retransmission, and keepalive logic.
- QUIC and TCP transport adapters.
- The `aioquic` dependency.
- Demo programs and the old protocol specification.

### Changed

- Package renamed from `gfsip` to `antares`, using a `src/` layout.
- Scope is now message formats and verification only: Audit Events and
  Domain Descriptors.
- Transport is out of scope; messages are carried over HTTP/3, A2A, MCP,
  TCP+TLS, or WebSockets.

### Kept and improved

- Audit: signed causal events, cycle detection, parent bound, missing-parent
  tracking, and deterministic state hashing.
- Federation: domain descriptors, validity windows, and version
  monotonicity.

### Added

- Real Ed25519 signing for domain descriptors (replacing the previous
  HMAC-based placeholder), with trust-anchor verification.
- Route loop detection and hop-limit enforcement.
- JSON Schemas for both message families.
- A 15-case conformance test suite.
- New specification (`ANTARES_SPEC.md`), README in English and Chinese,
  and the conformance requirements document.

## 1.x — Legacy

The earlier v1.0/v1.1 GFSIP transport work remains available in the Git
history of this repository.
