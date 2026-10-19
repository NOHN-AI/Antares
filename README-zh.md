# Antares

**面向 AI 智能体的审计与联邦层。** 一个小型、与传输无关的消息层，回答 A2A、
MCP 与普通 JSON-RPC 都没有回答的问题：

- **Audit（审计）**：签名因果事件 + 因果锥承诺，使"这就是全部事件"从声明
  变成可校验的事实。
- **Evidence（证据）**：Merkle 绑定的证据块、盐化承诺、带包含证明的选择性披露。
- **Rebuttable claims（可反驳主张）**：决策可以被论证、被挑战、被答复、被裁决，
  全过程都留在同一条日志里。
- **Attestation（审计的审计）**：审计结论本身也是一条事件，因此可以被再次审计。
- **Federation（联邦）**：签名域描述符、密钥轮换预承诺、撤销、网关持有性证明、
  无环路由。

Antares **不是**传输协议。它不定义握手、会话、流、帧头或重传。消息可以跑在
HTTP/3、A2A、MCP、TCP+TLS 或 WebSockets 之上。

## 为什么需要

智能体跨组织协作时，真正重要的是两件事：

1. **到底是什么决定了这件事，我能看出它没被改吗？** 签名事件记录了 actor、
   密钥、算法、父事件，以及这些父事件所承诺的**历史锥**。验证方重算锥根即可；
   被截断的历史会暴露，而不是看起来合理。
2. **该找谁，这个身份是真的吗？** 签名描述符列出网关与信任锚；换钥必须由旧钥
   预承诺新钥；撤销条目写在签名描述符内部。

遥测可以采样、可以丢；证据不行。Antares 面向第二类：产出物必须能被第三方
**离线**验证，无需信任你的日志或基础设施。

## 安装

```bash
pip install antares
```

运行依赖：`cbor2`、`cryptography`。安装后获得 `antares-verify` 命令行。

## 快速开始 — 审计

```python
from antares import AuditLog, AuditEvent, generate_keypair, verify_cone

private_key, public_key = generate_keypair()
log = AuditLog(signing_key=private_key, context_id=b"conversation-1",
               key_id="urn:antares:key:planner")

event = AuditEvent(
    event_id="urn:example:event:1",
    actor_node_id="urn:example:node:planner",
    actor_domain_id="urn:example:domain:us",
    event_type="order.approve",
    rule_id="policy.ap",
    rule_version="1.2",
    observed_at="2026-10-19T10:00:00Z",
    logical_clock=1,
)
log.add(event)
assert log.verify_signature(event, public_key)

report = verify_cone([e.to_wire() for e in log.list_events()])
assert report["ok"] and report["complete"]
```

`add` 强制的不变量：

- 不允许自环、不允许因果环（`CAUSAL_CYCLE`）；
- 直接父事件最多 8 个（`TOO_MANY_PARENTS`）；
- 缺失父事件写进**签名体内**的 `ur`，不会被静默丢弃；
- `cr`/`cs` 承诺父锥，事后截断可被检测。

## 快速开始 — 可反驳主张

```python
from antares import Warrant, CounterEvidence, WarrantLedger

warrant = Warrant(
    warrant_id="w1",
    target_cone_root=event.cone_root,
    target_size=event.cone_size + 1,
    decision_event_id=event.event_id,
    necessity="necessary",
    rule_id="policy.ap",
    asserted_at="2026-10-19T10:00:01Z",
).sign(private_key, "urn:antares:key:planner")

ledger = WarrantLedger()
ledger.add_warrant(warrant)
assert ledger.state_of("w1") == "ASSERTED"

counter = CounterEvidence(
    counter_id="c1", warrant_id="w1",
    counter_cone_root="sha256:" + "11" * 32,
    slot="alternatives", kind="evidence",
    expected="cmt:" + "22" * 32, actual="cmt:" + "33" * 32,
).sign(private_key, "urn:antares:key:planner")

ledger.add_counter(counter)
assert ledger.state_of("w1") == "CHALLENGED"
```

状态由消息集合推导，不依赖摄入顺序；无法消解的冲突落在 `CHALLENGED`，
绝不会静默产生赢家。

## 快速开始 — 证据包

```python
from antares import EvidenceSet, build_bundle, verify_bundle, write_bundle

evidence = EvidenceSet()
evidence.add(b"invoice-42")
evidence.add(b"chat-log")

data = build_bundle(
    events=log.wire_list(),
    evidence=evidence,
    disclosures=[evidence.disclose([0])],   # 只披露一块，仍可证明整个集合
)
write_bundle("case-42.ant", data)

keys = {"urn:antares:key:planner": public_key}
report = verify_bundle(data, keys)
assert report["ok"]
```

```bash
antares-verify case-42.ant --key urn:antares:key:planner=<hex-pubkey>
```

证据包内含事件、检查点、审计结论、证据块、披露证明与时间戳令牌；校验顺序是
先验清单哈希，再验每个签名，最后验因果闭包。

## 快速开始 — 联邦

```python
import time
from antares import (
    FederationRegistry, DomainDescriptor, Gateway, TrustAnchor,
    sign_descriptor, generate_keypair, key_fingerprint,
)

domain_priv, domain_pub = generate_keypair()
domain = "urn:antares:domain:remote"
registry = FederationRegistry("urn:antares:domain:local")
registry.add_trust_anchor(domain, domain_pub,
                          next_key_hash=key_fingerprint(domain_pub))

now = time.time()
descriptor = DomainDescriptor(
    domain_id=domain, descriptor_version=1,
    valid_from=now - 60, valid_until=now + 3600,
    gateways=[Gateway("http3://gw.example:443", "http3", 10)],
    trust_anchors=[TrustAnchor("urn:antares:key:remote", "ed25519",
                               domain_pub)],
)
sign_descriptor(descriptor, domain_priv)
registry.register(descriptor)
```

## 目录结构

```
src/antares/
  types.py         # 版本、错误码、边界、算法
  cbor_utils.py    # 规范化 CBOR
  signing.py       # ed25519 + 混合签名提供者、签名编码
  envelope.py      # 所有消息族共用的签名信封
  merkle.py        # RFC 6962 结构、包含证明
  audit.py         # AuditEvent、AuditLog、锥校验
  checkpoint.py    # 检查点、跨域互签、分叉检测
  disclosure.py    # 盐化承诺、证据集、证明
  warrant.py       # 主张、反证、推导状态
  attestation.py   # 带算子集指纹的审计结论
  bundle.py        # .ant 证据包
  federation.py    # 描述符、轮换、撤销、路由
  cli.py           # antares-verify
  vectors.py       # 确定性一致性向量
schemas/           # JSON Schema
tests/             # 一致性测试 + 向量
ANTARES_SPEC.md    # 规范（v2.1）
CONFORMANCE.md     # 要求清单（C/E/A/K/P/D/W/T/B/F/V）
```

## 与其他标准的关系

| 标准 | 层级 | 关系 |
|---|---|---|
| HTTP/3（QUIC） | 传输 | 承载 Antares 消息。 |
| MCP | 工具/资源协议 | Antares 增加签名事件与身份。 |
| A2A | 智能体 RPC | Antares 是调用之下的审计/联邦层。 |
| TLS 1.3 | 通道安全 | 认证连接；Antares 对内容签名。 |
| SCITT / Sigstore / in-toto | 透明日志与证明 | 证据模型兼容。Antares 增加因果锥完备性、可反驳主张与选择性披露；入口级透明日志仍可作为后端。 |

## 兼容性

2.1 与 2.0 **不**线格式兼容：信封签名纳入 `key_id` 与 `algorithm`，`ctx`
进入每条消息，2.0 的空承诺 payload digest 被证据根取代。2.1 验证器直接拒绝
`v: "2.0"`，不做重新解释。

## 一致性

见 `CONFORMANCE.md`、`tests/vectors/v2.1.json`，以及：

```powershell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -v
```

## 更新日志

- `CHANGELOG_v2.1.md` — 证据闭包、可反驳、披露、留存。
- `CHANGELOG_v2.0.md` — 重定义为审计与联邦层。

## 许可证

- 代码：Apache License 2.0。
- 规范：CC BY 4.0。
