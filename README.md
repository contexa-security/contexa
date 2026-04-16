<img src="logo.png" alt="Contexa Logo" width="80" align="left" />

# CONTEXA

**Open-source AI Native Post-Auth Runtime Control Plane for Spring**

<br clear="left" />

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5-green.svg)](https://spring.io/projects/spring-boot)

> Security does not end at login.
> CONTEXA continuously evaluates authenticated runtime behavior and applies zero-trust controls inside the application.

- **Website:** https://ctxa.ai
- **Demo / Verification Console:** https://demo.ctxa.ai
- **Documentation:** https://docs.ctxa.ai
- **Architecture:** https://docs.ctxa.ai/docs/reference/architecture/overview.html
- **Public Benchmark:** https://ctxa.ai/benchmark
- **Security Contact:** https://ctxa.ai/.well-known/security.txt
- **GitHub:** https://github.com/contexa-security/contexa

---

## What CONTEXA Is

CONTEXA is an open-source AI Native Post-Auth Runtime Control Plane.

It is built for what happens after authentication succeeds:

- request-time runtime zero trust
- authenticated human access decisions
- workload and service-client continuity
- delegated agent execution governance
- exploit-window compensating controls
- verification-backed benchmark and proof generation

## What CONTEXA Is Not

CONTEXA is not:

- a vulnerability scanner
- a binary analysis engine
- a penetration testing framework
- a SIEM replacement
- a generic IAM admin SaaS product

CONTEXA complements upstream security discovery by constraining authenticated runtime behavior after risk is discovered.

## Why CONTEXA

Most serious breaches happen after successful authentication.

The attacker already has one or more of the following:

- a valid session
- a valid token
- a valid workload credential
- an approved tool path
- an authenticated delegated agent

Traditional security often concentrates on login, network edges, and endpoint state.
CONTEXA starts where those layers leave off: inside the application runtime, at request time, with zero-trust decisions that can challenge, block, contain, or escalate.

| Dimension | Traditional Security | With CONTEXA |
|---|---|---|
| Decision point | Login or coarse policy checkpoints | Every protected request |
| Scope | Network, endpoint, perimeter | Inside the application runtime |
| Subject | Mostly users and devices | Humans, workloads, service clients, delegated agents |
| Response | Allow or deny | ALLOW, CHALLENGE, BLOCK, ESCALATE, PENDING_ANALYSIS |
| Proof | Logs and dashboards | Verification, benchmark, publication-ready proof |

## Glasswing Relevance

**Glasswing discovers. CONTEXA constrains.**

Anthropic Project Glasswing represents upstream AI-driven defensive discovery.
CONTEXA addresses the downstream runtime problem that remains after discovery:

- how to reduce exploit windows before remediation is complete
- how to constrain authenticated humans, workloads, and delegated agents
- how to apply compensating controls in production
- how to prove those controls with verification and benchmark artifacts

This repository contains the open-source runtime control engine for that downstream layer.

## Project Status

- Current public OSS version: `0.1.0`
- Repository stage: initial public open-source release
- Core focus: post-authentication runtime control inside Spring applications

CONTEXA should be evaluated as an early but serious security infrastructure project.
Its public scale is still developing, but the category it addresses is already operationally important: constraining authenticated runtime behavior after risk is discovered and before remediation is complete.

## Why Review CONTEXA at an Early OSS Stage

CONTEXA does not yet claim mature open-source scale.
It should instead be assessed on structural security relevance:

- it addresses the post-authentication runtime problem that remains after upstream discovery
- it operates at the application layer, where authenticated requests are actually executed
- it provides public documentation, benchmark surfaces, and a security contact path
- it is built as an open-source runtime control engine rather than a marketing-only concept
- it is relevant to downstream exploit-window reduction for authenticated humans, workloads, service clients, and delegated agents

## Open-source Core and Enterprise Surfaces

This repository contains the open-source core platform:

- `contexa-core`
- `contexa-identity`
- `contexa-iam`
- `contexa-common`
- `contexa-autoconfigure`
- `spring-boot-starter-contexa`

Commercial and enterprise operational surfaces exist separately.
Those surfaces include multi-tenant operations, publication workflows, advanced review planes, and commercial runtime delivery features.

The open-source core remains a meaningful platform on its own.
It provides the runtime decision, control, and integration foundation.

## Quick Start

### 1. Add the dependency

```gradle
dependencies {
    implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"
}
```

### 2. Enable AI security

```java
@SpringBootApplication
@EnableAISecurity
public class MyApplication {
}
```

### 3. Protect resources

```java
@Protectable
@PostMapping("/api/users/{id}/disable")
public void disableUser(@PathVariable Long id) {
    service.disable(id);
}
```

For full setup, configuration, and architecture guidance, use the documentation site at `https://docs.ctxa.ai`.

## Runtime Zero Trust Actions

Every protected request receives a runtime decision.

| Action | HTTP | Meaning |
|---|---|---|
| `ALLOW` | 200 | Behavior is within acceptable bounds |
| `CHALLENGE` | 401 | Additional verification is required |
| `BLOCK` | 403 | Active risk requires immediate denial |
| `ESCALATE` | 423 | Human review or higher-friction handling is required |
| `PENDING_ANALYSIS` | 503 | Runtime analysis has not completed yet |

## How It Works

```text
Request (Human / Workload / Service Client / Delegated Agent)
  |
  +-- contexa-identity
  |     Authentication flows, MFA, adaptive challenges
  |
  +-- contexa-iam
  |     URL, method, and resource policy evaluation
  |     @Protectable method protection
  |
  +-- contexa-core
        Context collection
        Behavioral analysis
        RAG and LLM reasoning
        Runtime zero-trust decision
        Control action application
```

## Modules

| Module | Responsibility |
|---|---|
| `contexa-core` | AI pipeline, LLM orchestration, RAG, autonomous security processing, runtime zero-trust state |
| `contexa-identity` | Authentication flows, MFA, passkey, adaptive zero-trust access control |
| `contexa-iam` | Dynamic authorization, policy evaluation, resource scanning, policy workflows |
| `contexa-common` | Shared annotations, DTOs, enums, contracts |
| `contexa-autoconfigure` | Spring Boot auto-configuration |
| `spring-boot-starter-contexa` | Starter entry point for community adoption |

## Key Capabilities

### Runtime Behavioral Security

CONTEXA compares each request against runtime context, history, and policy signals to detect behavior that static rules miss.

### Dynamic Authorization

CONTEXA evaluates URL, method, and resource-level access decisions and supports method-level protection through `@Protectable`.

### AI-native Control Decisions

CONTEXA can challenge, block, escalate, or defer based on runtime analysis instead of relying only on static roles and ACLs.

### Proof-backed Security

CONTEXA is designed to support verification, replay, benchmarking, and publication-ready reporting rather than simple vendor claims.

## Operating Modes

| Mode | Infrastructure | Use Case |
|---|---|---|
| `standalone` | PostgreSQL + Ollama | Development and smaller deployments |
| `distributed` | PostgreSQL + Redis + Kafka | Production and multi-instance deployments |

```yaml
contexa:
  infrastructure:
    mode: standalone
```

## Trust and Public References

- Main site: https://ctxa.ai
- Demo / verification console: https://demo.ctxa.ai
- Documentation site: https://docs.ctxa.ai
- Architecture overview: https://docs.ctxa.ai/docs/reference/architecture/overview.html
- Public benchmark entry: https://ctxa.ai/benchmark
- Security policy: [SECURITY.md](SECURITY.md)
- Public security.txt: https://ctxa.ai/.well-known/security.txt
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Maintainer statement: [MAINTAINERS.md](MAINTAINERS.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.


