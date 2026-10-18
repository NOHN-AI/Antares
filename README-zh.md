# Antares

**面向 AI 智能体的审计与联邦层。** 一个小型、与传输无关的消息层，
提供 A2A、MCP 和普通 HTTP/JSON-RPC 都没有的两样东西：

- **Audit（审计）**：签名因果事件，含环检测、缺失父事件追踪和确定性
  状态哈希。
- **Federation（联邦）**：签名域描述符、信任锚验签，以及无环的跨域路由。

Antares **不是**传输协议。它不定义握手、会话、流、帧头或重传。
Antares 消息可以跑在你已有的任何承载上：HTTP/3、A2A、MCP、TCP+TLS
或 WebSockets。

## 为什么需要

当智能体跨组织协作时，有两个问题最重要：

1. **到底是谁决定的？** 签名因果事件回答：谁产生的、依赖了什么、
   看到了什么状态——无需信任运营方日志即可独立验证。
2. **该找谁，这个身份是真的吗？** 签名域描述符列出网关和信任锚；
   注册中心校验签名、有效期窗口和版本单调递增。

A2A 和 MCP 定义“怎么调用”智能体，Antares 提供这些调用之下的
不可抵赖证据与身份层。

## 安装

```bash
pip install antares
```

运行依赖：`cbor2`、`cryptography`。

## 快速开始 — 审计

```python
from antares import AuditLog, AuditEvent, generate_keypair

private_key, public_key = generate_keypair()
log = AuditLog(signing_key=private_key, context_id=b"conversation-1")

event = AuditEvent(
    event_id="urn:example:event:1",
    actor_node_id="urn:example:node:planner",
    actor_domain_id="urn:example:domain:us",
    event_type="order.approve",
    rule_id="policy.ap",
    rule_version="1.2",
    observed_at="2026-10-18T10:00:00Z",
    logical_clock=1,
)
log.add(event)
assert log.verify_signature(event, public_key)
```

`add` 时强制的不变量：

- 不允许自环、不允许因果环（`CAUSAL_CYCLE`）；
- 直接父事件最多 8 个（`TOO_MANY_PARENTS`）；
- 缺失的父事件记录在 `unresolved_parents`，不拒绝。

## 快速开始 — 联邦

```python
import time
from antares import (
    FederationRegistry, DomainDescriptor, Gateway, TrustAnchor,
    sign_descriptor, generate_keypair,
)

domain_priv, domain_pub = generate_keypair()
remote = "urn:antares:domain:remote"

registry = FederationRegistry("urn:antares:domain:local")
registry.add_trust_anchor(remote, domain_pub)

now = time.time()
descriptor = DomainDescriptor(
    domain_id=remote,
    descriptor_version=1,
    valid_from=now - 60,
    valid_until=now + 3600,
    gateways=[Gateway("http3://gw.example:443", "http3", 10)],
    trust_anchors=[TrustAnchor("k1", "ed25519", domain_pub)],
)
sign_descriptor(descriptor, domain_priv)
registry.register(descriptor)

route = registry.route_query(
    target_domain=remote, visited_domains=[], max_hops=4
)
print(route["next_hop"])
```

注册中心会拒绝过期、版本回退和未签名的描述符；`route_query`
强制跳数限制和已访问域环检测。

## 目录结构

```
src/antares/
  types.py        # 版本、错误码、边界
  cbor_utils.py   # 规范化 CBOR
  signing.py      # Ed25519 密钥对、签名/验签、信任锚
  audit.py        # AuditEvent、AuditLog
  federation.py   # DomainDescriptor、FederationRegistry
  business.py     # 确定性处理器协议与状态哈希
tests/            # 15 个 unittest 用例
schemas/          # 两类消息的 JSON Schema
ANTARES_SPEC.md   # 消息规范
```

## 与其他标准的关系

| 标准 | 层级 | 关系 |
|---|---|---|
| HTTP/3（QUIC） | 传输 | 承载 Antares 消息。 |
| MCP | 工具/资源协议 | Antares 增加签名事件与身份。 |
| A2A | 智能体 RPC | Antares 提供审计/联邦层。 |
| TLS 1.3 | 通道安全 | 认证连接；Antares 对内容签名。 |

## 一致性

见 `CONFORMANCE.md` 与测试套件。实现须生成规范化 CBOR、强制因果
不变量，并按规范校验描述符签名与路由规则。

## 更新日志

见 `CHANGELOG_v2.0.md`。

## 许可证

- 代码：Apache License 2.0。
- 规范：CC BY 4.0。
