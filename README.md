<p align="center">
  <img src="assets/banner.svg" alt="ANTARES banner" style="width:100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/protocol-D4AF37?style=flat-square" alt="protocol">
  <img src="https://img.shields.io/badge/quic-D4AF37?style=flat-square" alt="quic">
  <img src="https://img.shields.io/badge/federation-D4AF37?style=flat-square" alt="federation">
  <img src="https://img.shields.io/badge/gfsip-v1.0-D4AF37?style=flat-square" alt="gfsip-v1.0">
</p>

<blockquote align="center">
  <em>Global Federated Stable Interoperability Protocol GFSIP v1.0</em>
</blockquote>

<p align="center">
  <a href="README-zh.md">简体中文</a> | English
</p>

<div style="max-width:880px;margin:0 auto;padding:0 16px">

## ✦ About

<p style="font-size:15px;line-height:1.8;color:#2C2C2C">ANTARES is GFSIP v1.0 — the Global Federated Stable Interoperability Protocol. It provides encrypted, multiplexed, recoverable cross-domain communication for services, AI agents, devices, and organizations, without a central authority. With QUIC as the mandatory transport layer and deterministic CBOR serialization, it has built-in session resumption, idempotent deduplication, and causal audit, serving as the stable foundation of a decentralized network.</p>

<p align="center">
  <img src="assets/overview.svg" alt="ANTARES overview" style="width:100%">
</p>

</div>

<p align="center">— ✦ —</p>

## ✦ Architecture (Plain Language)

> **In one sentence:** ANTARES lets your service, AI agent or device talk to anyone else — safely, across organizations, **with no central server in the middle**.

```mermaid
flowchart TB
    UP["👤 Your service · AI agent · device (caller)<br/>business request: payment · message · data sync"]

    A1["🚪 reference-impl/gfsip/endpoint.py · transport.py<br/>open the QUIC connection, enter the GFSIP session"]
    A2["🤝 auth.py · frame.py<br/>mutual auth + version negotiation: 44-byte fixed header · ALPN gfsip/1"]
    A3["📜 GFSIP_v1.0_protocol_spec.md · gfsip-state-machine.json<br/>spec + state machine: legal states and transitions"]
    A4["🔌 channel.py<br/>open lanes: multiplex many channels over one session"]
    A5["🧬 cbor_utils.py<br/>send data: deterministic CBOR encoding, frame by frame"]
    A6["🔁 dedupe.py<br/>idempotent dedupe: idempotency keys + windowed dedup, run exactly once"]
    A7["🔄 resume.py<br/>survive a network switch: resume without re-authenticating"]
    A8["📒 audit.py · signing.py<br/>causal audit: signed events + declared causal parents, reject self-loops and cycles"]
    A9["🌐 federation.py<br/>cross-domain routing: signed DomainDescriptor + multi trust anchor + fault isolation"]
    A10["⚠️ gfsip-error-registry.json · gfsip-message-schema.json<br/>error-code registry + message schema, uniform error numbering"]
    A11["✅ gfsip-conformance-checklist.csv · CONFORMANCE.md<br/>conformance checklist and pass / fail criteria"]

    OUT["📦 Cross-domain session achieved<br/>encrypted · resumable · auditable · idempotent"]
    HUMAN["✍️ Human sign-off on the conformance result<br/>the final call stays outside the algorithm"]

    UP --> A1
    A1 --> A2
    A2 --> A3
    A3 --> A4
    A4 --> A5
    A5 --> A6
    A6 --> A7
    A7 --> A8
    A8 --> A9
    A9 --> A10
    A10 --> A11
    A11 --> OUT
    OUT --> HUMAN

    classDef cUp fill:#F5F5F5,stroke:#9E9E9E,stroke-width:1px,color:#424242
    classDef cIn fill:#E8F0FE,stroke:#4285F4,stroke-width:1px,color:#173A66
    classDef cCore fill:#FFF8E1,stroke:#C9A96E,stroke-width:1px,color:#5B4614
    classDef cSide fill:#F3E8FD,stroke:#8E44AD,stroke-width:1px,color:#4A235A
    classDef cOut fill:#E6F4EA,stroke:#34A853,stroke-width:1px,color:#14512B
    class UP cUp
    class A1 cIn
    class A2,A4,A5,A6,A7,A9 cCore
    class A3,A8,A10,A11 cSide
    class OUT,HUMAN cOut
```

**How to read it**

1. Read top-down: it is **one session's timeline** — a connection is established, authenticated, opened, used, recovered, audited and routed; a request goes in at the top and a signed cross-domain session comes out at the bottom.
2. Every box names the actual **`reference-impl/gfsip/*.py`** implementation plus the matching spec artifact, so you can jump straight from a step to its code.
3. The key boundary: there is **no central authority** — auditing and federation are optional **Core / Audit / Federation** profiles, not mandatory layers.

📖 Every term explained in one plain sentence → [Glossary](./GLOSSARY.md)

## ✦ Core Capabilities

<div style="max-width:880px;margin:0 auto;padding:0 16px">

<table style="width:100%;border-collapse:collapse;font-size:14px">
  <tr><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">#</th><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">Capability</th><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">Description</th></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">1</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Encrypted Session</strong></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Mutually authenticated TLS or token-authenticated sessions over QUIC</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">2</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Multiplexing</strong></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Independent logical channels within a single session</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">3</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Session Resumption</strong></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Resume sessions without re-authentication after network handover</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">4</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Idempotent Side Effects</strong></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Windowed deduplication via idempotency keys</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">5</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Causal Audit (optional)</strong></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Signed event records with declared causal predecessors</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">6</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Cross-Domain Federation</strong></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Multi-trust-anchor routing + signed domain descriptors</td></tr>
  <tr><td style="padding:8px">7</td><td style="padding:8px"><strong>Fault Isolation</strong></td><td style="padding:8px">A single domain failure does not block intra-domain traffic</td></tr>
</table>

</div>

<p align="center">— ✦ —</p>

## ✦ Wire Format

<div style="max-width:880px;margin:0 auto;padding:0 16px">

<p style="font-size:15px;line-height:1.8;color:#2C2C2C">GFSIP uses a <strong>44-byte fixed-length header</strong> over QUIC, with ALPN <code style="background:#F5F0E6;padding:2px 6px;border-radius:3px;color:#C9A96E">gfsip/1</code>. Extension headers use deterministic CBOR (big-endian, shortest encoding). 18 standard message types (<code>0x01</code>–<code>0x16</code>) cover the full lifecycle: handshake, channel management, data transfer, session resumption, audit events, and federation routing.</p>

</div>

<p align="center">— ✦ —</p>

## ✦ Repository Contents

<div style="max-width:880px;margin:0 auto;padding:0 16px">

<table style="width:100%;border-collapse:collapse;font-size:14px">
  <tr><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">File</th><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">Purpose</th></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><code>GFSIP_v1.0_protocol_spec.md</code></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Full protocol specification (33 sections)</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><code>gfsip-state-machine.json</code></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Machine-readable state machine definition</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><code>gfsip-message-schema.json</code></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Logical message JSON Schema</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><code>gfsip-error-registry.json</code></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Numeric error code registry</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><code>gfsip-conformance-checklist.csv</code></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Conformance test checklist</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><code><a href="./CONFORMANCE.md">CONFORMANCE.md</a></code></td><td style="padding:8px;border-bottom:1px solid #F0EAD9">Conformance testing guide — how to derive your own test cases from the normative artifacts (for third-party evaluators)</td></tr>
  <tr><td style="padding:8px"><code>reference-impl/</code></td><td style="padding:8px">Python reference implementation — frame codec, state machine, channel management, authentication, deduplication, resumption, audit, federation, end-to-end demo (9/9 conformance vectors passing)</td></tr>
</table>

</div>

<p align="center">— ✦ —</p>

## ✦ Protocol Profile

<div style="max-width:880px;margin:0 auto;padding:0 16px">

<p style="font-size:15px;line-height:1.8;color:#2C2C2C"><strong style="color:#C9A96E">Core/1 (mandatory)</strong> — QUIC transport, version negotiation, mutual authentication, session and channel management, session resumption, structured errors, graceful shutdown.</p>

<p style="font-size:15px;line-height:1.8;color:#2C2C2C"><strong style="color:#C9A96E">Audit/1 (optional)</strong> — Signed causal event records with declared causal predecessors, actor identity, rule version, and pre/post state hashes; rejects self-loops and known cycles.</p>

<p style="font-size:15px;line-height:1.8;color:#2C2C2C"><strong style="color:#C9A96E">Federation/1 (optional)</strong> — Cross-domain routing via signed <code>DomainDescriptor</code> objects, multi-trust-anchor configuration, descriptor expiration / revocation, and fault isolation.</p>

</div>

<p align="center">— ✦ —</p>

## ✦ Quick Start

```bash
# Install SDK (PyPI)
pip install gfsip

# Run end-to-end demo (clone the repo to get demo files)
git clone https://github.com/nohn3043-arch/Antares.git
cd Antares/reference-impl
pip install -r requirements.txt
python demo.py                # Sync API demo: handshake -> channel -> data -> dedup -> resume
python async_demo.py          # Async API demo: await connect/open_channel/send (zero manual pump)
python -m gfsip.conformance   # 9/9 Section 28 minimum vectors — author self-test, see CONFORMANCE.md
```

<p align="center">— ✦ —</p>

## ✦ Application Scenarios

<div style="max-width:880px;margin:0 auto;padding:0 16px">

- **AI Agent Networks** — Multi-agent task collaboration across organizational boundaries, with auditable trails
- **Enterprise Integration** — Cross-organizational workflow orchestration without a central authority
- **IoT / Edge** — Device-to-cloud session resumption under network handover
- **Finance / Compliance** — Signed causal audit chains for regulatory reporting
- **Healthcare** — Federated data exchange with domain-level policy enforcement
- **Robotics** — Reliable command channels for idempotent safe operations

</div>

<p align="center">— ✦ —</p>

## ✦ Project Status

<div style="max-width:880px;margin:0 auto;padding:0 16px">

<table style="width:100%;border-collapse:collapse;font-size:14px">
  <tr><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">Milestone</th><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">Status</th></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">Spec v1.0 (interface frozen)</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">✅ Done</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">Machine-readable state machine and schemas</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">✅ Done</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">Python reference implementation (9/9 conformance)</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">✅ Done</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">PyPI package release (pip install gfsip)</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">✅ Done</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">Async high-level API (AsyncEndpoint, zero manual pump)</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">✅ Done</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">Independent second implementation</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">🔲 In progress</td></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9">Public interoperability report</td><td style="padding:8px;border-bottom:1px solid #F0EAD9">🔲 Todo</td></tr>
  <tr><td style="padding:8px">Production pilot domain</td><td style="padding:8px">🔲 Todo</td></tr>
</table>

</div>

<p align="center">— ✦ —</p>

## ✦ Ecosystem

ANTARES is a member of the NOHN AI ecosystem - a family built on deterministic executive kernels and auditable causal semantics. Public projects:

| Project | Repository | Role |
|---|---|---|
| **Second-Perspective Engine** | [nohn3043-arch/second-perspective-open](https://github.com/nohn3043-arch/second-perspective-open) | AI decision control infrastructure - public trust layer (spec / verifier / evidence) |
| **Antares** | [nohn3043-arch/Antares](https://github.com/nohn3043-arch/Antares) | GFSIP v1.0 - federated stable interoperability protocol with causal audit |
| **ai-draw** | [NOHN-AI/ai-draw](https://github.com/NOHN-AI/ai-draw) | AI-drawing prompt console |
| **Second-Reality** | [nohn3043-arch/Second-Reality](https://github.com/nohn3043-arch/Second-Reality) | Virtual-world infrastructure (Constitution / Law / Bridge) |

<p align="center">— ✦ —</p>

## ✦ License

This repository uses a **dual-track license**:

<table style="width:100%;border-collapse:collapse;font-size:14px">
  <tr><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">Content</th><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">License</th><th style="text-align:left;color:#C9A96E;padding:8px;border-bottom:1px solid #E5DCC4">File</th></tr>
  <tr><td style="padding:8px;border-bottom:1px solid #F0EAD9"><strong>Code implementation</strong> (the Python package <code>gfsip</code> under <code>reference-impl/</code>)</td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License 2.0</a></td><td style="padding:8px;border-bottom:1px solid #F0EAD9"><a href="./LICENSE"><code>LICENSE</code></a></td></tr>
  <tr><td style="padding:8px"><strong>Protocol specification and documentation</strong> (<code>GFSIP_v1.0_protocol_spec.md</code>, <code>gfsip-*.json</code>, <code>gfsip-*.csv</code>, <code>assets/</code> diagrams)</td><td style="padding:8px"><a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a></td><td style="padding:8px"><a href="./LICENSE-SPEC.md"><code>LICENSE-SPEC.md</code></a></td></tr>
</table>

Apache-2.0 permits commercial use, modification, and distribution, and includes an **express patent grant**; CC BY 4.0 permits any use and redistribution (including commercial use) with attribution only — the open attribution license for the specification serves GFSIP's goal of dissemination as an open standard.

> **Irrevocable notice**: Versions up to and including v1.0 were previously released in their entirety under CC BY 4.0 (including code). That license is irrevocable under its terms, and those versions will remain permanently usable under CC BY 4.0. The dual-track arrangement above takes effect from the next version.

- **Contact**: International / Global — [ai@nohnlins.com](mailto:ai@nohnlins.com) · China — [lin@secondai.top](mailto:lin@secondai.top)

<p align="center">
  <a href="https://github.com/nohn3043-arch">GitHub</a>
  &nbsp;·&nbsp;
  <a href="https://www.nohnlins.com/">nohnlins.com</a>
  &nbsp;·&nbsp;
  <a href="mailto:ai@nohnlins.com">ai@nohnlins.com</a>
</p>
<p align="center"><sub>NOHN AI · ANTARES</sub></p>
