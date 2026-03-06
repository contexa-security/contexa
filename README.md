<p align="center">
  <strong>CONTEXA</strong><br>
  <em>AI-Native Zero Trust Security Platform for Spring</em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://github.com/contexa-security/contexa/actions/workflows/ci.yml"><img src="https://github.com/contexa-security/contexa/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Java-21-orange.svg" alt="Java 21">
  <img src="https://img.shields.io/badge/Spring%20Boot-3.5.4-brightgreen.svg" alt="Spring Boot">
</p>

---

## The Problem

Every major breach in the last 3 years happened **after successful authentication**.
Credentials were valid. Sessions were legitimate. The attacker was already inside.

Rule-based security (`@PreAuthorize`, RBAC) cannot detect threats that look like normal, authorized behavior.

## What Contexa Does

Contexa analyzes **the context of every action after authentication** using AI, and autonomously detects and responds to anomalies in real time.

- **384-dimensional context vectors** per request
- **Behavioral pattern learning** per user
- **Real-time threat detection** at 8ms average latency
- **Zero-downtime migration** via Shadow Mode

```java
@SpringBootApplication
@EnableAIZeroTrust
public class MyApp { }
```

One annotation. AI security is active.

---

## Core Architecture

### HCAD (Hierarchical Context-Aware Detection)

| Path | Traffic | Latency | Description |
|------|---------|---------|-------------|
| Hot Path | 98% | 5-30ms | Fast vector-based decision |
| Cold Path | 2% | 50ms-1s | Deep AI analysis with LLM reasoning |

### Shadow Mode (4-Stage Migration)

| Stage | Mode | Description |
|-------|------|-------------|
| 1 | **Shadow** | AI observes only. No enforcement. Zero risk. |
| 2 | **Advisory** | AI recommends. Human decides. |
| 3 | **Hybrid** | AI blocks clear threats. Human handles edge cases. |
| 4 | **Autonomous** | Full AI security with human oversight. |

Deploy in production on Day 1 with zero risk. Graduate to full autonomy over months.

### 15 AI Labs

Specialized AI engines for policy, risk, behavior, anomaly, threat, context, and more. Each lab operates independently at 5-50ms response time.

---

## Quick Start

```gradle
implementation 'io.contexa:spring-boot-starter-contexa:0.1.0'
```

```yaml
# application.yml
contexa:
  ai:
    mode: SHADOW
    labs: [policy, risk]
  vector:
    dimensions: 384
```

```java
@AISecured(risk = RiskLevel.HIGH)
@DeleteMapping("/api/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}
```

---

## Modules

| Module | Description |
|--------|-------------|
| `contexa-common` | Shared annotations, DTOs, enums |
| `contexa-core` | Core engine: HCAD, vector analysis, orchestration |
| `contexa-identity` | Authentication: MFA, DSL-based filter chain |
| `contexa-iam` | Access control: XACML, ABAC, dynamic policy |
| `contexa-mcp` | AI integration via MCP (Model Context Protocol) |
| `contexa-autoconfigure` | Spring Boot auto-configuration |
| `spring-boot-starter-contexa` | Starter dependency |

---

## Community vs Enterprise

| | Community (OSS) | Enterprise |
|---|---|---|
| Shadow Mode | Yes | Yes |
| HCAD Detection | Yes | Yes |
| AI Labs (core) | Yes | Yes |
| SOAR Integration | - | Yes |
| Monitoring (Grafana/Prometheus) | - | Yes |
| Enterprise Dashboard | - | Yes |
| Priority Support | - | Yes |

---

## Roadmap

| Version | Milestone |
|---------|-----------|
| **v0.1.0** (current) | Shadow Mode + 2 AI Labs |
| v0.2.0 | 5 AI Labs + Advisory Mode |
| v0.3.0 | 10 AI Labs + Hybrid Mode |
| v1.0.0 | 15 AI Labs + Autonomous Mode (production-ready) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[Apache License 2.0](LICENSE) - Free to use, modify, and distribute.

---

<p align="center">
  <a href="https://github.com/contexa-security/contexa">GitHub</a> &middot;
  <a href="https://github.com/contexa-security/contexa/issues">Issues</a> &middot;
  <a href="https://github.com/contexa-security/contexa/discussions">Discussions</a>
</p>
