<img src="logo.png" alt="Contexa Logo" width="80" align="left" />

# CONTEXA

**AI-Native Zero Trust Security Platform for Spring**

<br clear="left" />

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5-green.svg)](https://spring.io/projects/spring-boot)

> Security doesn't end at login.
> Contexa continuously verifies every request after authentication using AI-driven behavioral analysis.

**[Website](https://www.ctxa.ai)** · **[Documentation](https://www.ctxa.ai/get-started.html)** · **[Architecture](https://ctxa.ai/en/docs/reference/architecture/overview)** · **[GitHub](https://github.com/contexa-security/contexa)**

---

## Why Contexa

Most breaches happen **after** successful authentication — valid credentials, valid sessions, but malicious intent.

Traditional security stops at login. Contexa starts there.

| | Traditional Security | + Contexa |
|---|---|---|
| **When** | At login only | Every request, continuously |
| **How** | Static rules (RBAC, ACL) | AI behavioral analysis |
| **Scope** | Network / endpoint | Inside the application |
| **Response** | Allow or deny | ALLOW · CHALLENGE · BLOCK · ESCALATE |

## Quick Start

**1. Add dependency**

```gradle
dependencies {
    implementation "io.contexa:spring-boot-starter-contexa:0.1.0"
}
```

**2. Enable AI Security**

```java
@SpringBootApplication
@EnableAISecurity
public class MyApplication { }
```

**3. Protect resources**

```java
@Protectable
@PostMapping("/api/users/{id}/disable")
public void disableUser(@PathVariable Long id) {
    service.disable(id);
}
```

That's it. Two annotations. Contexa handles the rest — context collection, AI analysis, and autonomous response.

> For full setup including database and LLM configuration, see the **[Get Started Guide](https://www.ctxa.ai/get-started.html)**.

## Zero Trust Actions

Every request receives a real-time AI verdict:

| Action | HTTP | Meaning |
|---|---|---|
| `ALLOW` | 200 | Behavior matches baseline — access granted |
| `CHALLENGE` | 401 | Suspicious signal detected — MFA required |
| `BLOCK` | 403 | Active threat — immediate denial |
| `ESCALATE` | 423 | Ambiguous — requires admin review |
| `PENDING_ANALYSIS` | 503 | Analysis in progress |

## How It Works

```
Request (Human / API / AI Agent)
  │
  ├─ contexa-identity ─── Authentication flows (Form / REST / OTT / Passkey / MFA)
  │
  ├─ contexa-iam ──────── Policy evaluation (URL / Method / Resource)
  │                        @Protectable method protection
  │
  ├─ contexa-core ─────── AI behavioral analysis
  │                        Baseline comparison + RAG + LLM reasoning
  │                        Zero Trust action decision
  │
  └─ Action ───────────── ALLOW │ CHALLENGE │ BLOCK │ ESCALATE │ PENDING_ANALYSIS
```

## Modules

| Module | Responsibility |
|---|---|
| `contexa-core` | AI pipeline, LLM orchestration, RAG, vector services, autonomous security processing, Zero Trust state |
| `contexa-identity` | Identity DSL, authentication flows (Form/REST/OTT/Passkey/MFA), adaptive MFA, Zero Trust access control |
| `contexa-iam` | Dynamic authorization, XACML-style evaluation, resource scanning, policy workflow, AI-assisted policy generation |
| `contexa-common` | Shared annotations, DTOs, enums, contracts |
| `contexa-autoconfigure` | Spring Boot auto-configuration layer |
| `spring-boot-starter-contexa` | Community starter (recommended entry point) |

## Key Capabilities

### Identity DSL
Model authentication flows through a DSL instead of scattered configuration. Supports form login, REST, OTT, passkey, and MFA combinations.

### Dynamic Authorization
Policy-driven access control at URL, method, and resource levels. `@Protectable` enables method-level Zero Trust protection with AI-assisted risk evaluation.

### AI Security Engine
LLM-powered behavioral analysis with contextual enrichment. Compares each request against learned baselines using vector retrieval (RAG) to detect anomalies that static rules miss.

### Autonomous Security Plane
Event-driven processing layer that collects security events, enriches context, runs AI analysis, and applies Zero Trust actions back into the platform in real-time.

## Operating Modes

| Mode | Infrastructure | Use Case |
|---|---|---|
| `standalone` | PostgreSQL + Ollama | Development, small deployments |
| `distributed` | + Redis + Kafka | Production, multi-instance |

```yaml
contexa:
  infrastructure:
    mode: standalone   # or distributed
```

## Links

- **Website**: [https://www.ctxa.ai](https://www.ctxa.ai)
- **Documentation**: [Get Started](https://www.ctxa.ai/get-started.html) · [Architecture](https://ctxa.ai/en/docs/reference/architecture/overview)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security**: [SECURITY.md](SECURITY.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
