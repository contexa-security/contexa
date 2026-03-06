<p align="center">
  <img src="logo.png" alt="Contexa Logo" width="100" />
</p>

<h1 align="center">CONTEXA</h1>

<p align="center">
  <strong>AI-Native Zero Trust Security Platform for Spring</strong>
</p>

Contexa is a Spring-first security platform that connects identity, authorization, AI-assisted risk evaluation, and response orchestration into one flow.
It is designed for teams that need to keep verifying requests after authentication, not just at login time.

## What Problem Contexa Solves

Many real-world incidents happen after successful authentication.
The session is valid, the credentials are valid, and the request looks normal enough to pass static access rules.

Traditional controls such as RBAC, URL rules, and `@PreAuthorize` remain necessary, but they are not enough on their own when the real signal lives in request context, session behavior, and evolving risk.

Contexa adds four things around a Spring application:

- identity flow orchestration with adaptive MFA
- policy-driven authorization for URL, method, and resource access
- AI-assisted analysis with vector retrieval and contextual enrichment
- Zero Trust response handling

## Core Value

- Continuous verification after login
- Policy and AI working together instead of separately
- Human-in-the-loop response for high-risk actions
- A path from standalone deployment to distributed operation

## Architecture Overview

```text
Request
  -> contexa-identity
     - form / rest / ott / passkey / mfa flows
  -> contexa-iam
     - URL / method / resource policy evaluation
     - @Protectable method protection
  -> contexa-core
     - AI analysis
     - vector retrieval / RAG
     - Zero Trust action decision
  -> Action
     - ALLOW | CHALLENGE | BLOCK | ESCALATE | PENDING_ANALYSIS
```

## Modules

| Module | Responsibility |
|---|---|
| `contexa-core` | AI pipeline orchestration, LLM integration, streaming, RAG, vector services, autonomous security processing, Zero Trust state handling |
| `contexa-identity` | Identity DSL, form/rest/OTT/passkey/MFA flows, adaptive MFA integration, Zero Trust access control |
| `contexa-iam` | Dynamic authorization, XACML-style evaluation, resource scanning, policy authoring workflow, AI-assisted policy generation APIs |
| `contexa-common` | Shared annotations, DTOs, enums, and contracts |
| `contexa-autoconfigure` | Spring Boot auto-configuration layer |
| `spring-boot-starter-contexa` | Community starter |

## Community Edition

The Community edition centers on these modules:

- `contexa-core`
- `contexa-identity`
- `contexa-iam`
- `spring-boot-starter-contexa`

The recommended entry point is the starter, not manual module-by-module wiring.

```gradle
dependencies {
    implementation "io.contexa:spring-boot-starter-contexa:0.1.0"
}
```

```java
@SpringBootApplication
@EnableAISecurity
public class MyApplication {
}
```

If method-level protection is needed, Contexa also provides `@Protectable`.

```java
@Protectable
@PostMapping("/api/users/{id}/disable")
public void disableUser(@PathVariable Long id) {
    service.disable(id);
}
```

A minimal configuration looks like this:

```yaml
contexa:
  infrastructure:
    mode: standalone

spring:
  ai:
    chat:
      model:
        priority: ollama,anthropic,openai
    embedding:
      model:
        priority: ollama,openai
    ollama:
      base-url: http://127.0.0.1:11434
      chat:
        options:
          model: qwen2.5:7b
          keep-alive: "24h"
    vectorstore:
      pgvector:
        table-name: vector_store
        dimensions: 1536
        distance-type: COSINE_DISTANCE
```

## Enterprise Edition

The Enterprise edition is available as a separate repository and extends Community capabilities with SOAR approval workflows, MCP tool calling, security response simulation, and extended metrics.
Contact the maintainers for Enterprise access.

## Key Capabilities

### 1. Identity DSL

`contexa-identity` lets teams model security configuration around authentication flows instead of scattered low-level configuration.
It supports form login, REST login, OTT, passkey, and MFA combinations through a DSL-oriented platform configuration model.

```java
@Bean
public PlatformConfig platformDslConfig(
        IdentityDslRegistry<HttpSecurity> registry,
        CustomDynamicAuthorizationManager authManager,
        AISessionSecurityContextRepository sessionRepo) throws Exception {

    return registry
            .global(http -> http
                    .authorizeHttpRequests(auth -> auth.anyRequest().access(authManager))
                    .securityContext(sc -> sc.securityContextRepository(sessionRepo)))
            .mfa(mfa -> mfa
                    .primaryAuthentication(auth -> auth.formLogin(Customizer.withDefaults()))
                    .ott(Customizer.withDefaults()))
            .session(Customizer.withDefaults())
            .build();
}
```

### 2. Policy-Driven Authorization

`contexa-iam` evaluates access at URL, method, and resource levels.
It does not stop at static role checks. Policy expressions can incorporate AI-aware conditions in the authorization path.

Typical IAM responsibilities include:

- dynamic URL authorization
- `@Protectable` method-level protection
- resource scanning and metadata registration
- policy authoring and workflow support
- AI-assisted policy generation APIs

### 3. AI-Native Security Core

`contexa-core` is the execution layer behind LLM calls, streaming, vector retrieval, and autonomous security processing.

Its responsibilities include:

- unified LLM orchestration
- model priority selection
- streaming response handling
- vector store retrieval and contextual enrichment
- autonomous security event processing
- Zero Trust action state handling

The Zero Trust action model exposed across the platform is:

- `ALLOW`
- `CHALLENGE`
- `BLOCK`
- `ESCALATE`
- `PENDING_ANALYSIS`

### 4. Autonomous Security Plane

Contexa includes an event-driven security processing layer that collects security events, enriches context, runs AI analysis, and applies response state back into the platform.
This is where `contexa-core`, `contexa-identity`, and `contexa-iam` connect most tightly.

### 5. SOAR and MCP (Enterprise)

SOAR approval workflows and MCP tool calling are available in the Enterprise edition.
See the Enterprise Edition section above for details.

## Operating Modes

Contexa supports two operating modes:

- `standalone`
  Default mode, favoring in-memory implementations and local operation.
- `distributed`
  Extended mode using distributed components such as Redis and Kafka where configured.

```yaml
contexa:
  infrastructure:
    mode: standalone
```

## Community vs Enterprise

| Capability | Community | Enterprise |
|---|---|---|
| Identity DSL | Yes | Yes |
| Adaptive MFA | Yes | Yes |
| Dynamic Authorization | Yes | Yes |
| LLM Orchestration | Yes | Yes |
| RAG and Vector Retrieval | Yes | Yes |
| Autonomous Security Plane | Yes | Yes |
| SOAR Approval Workflow | - | Available separately |
| MCP Tool Calling | - | Available separately |
| Simulation | - | Available separately |
| Extended Metrics and Dashboard | - | Available separately |

## Who Contexa Is For

Contexa fits teams that:

- run Spring Security-based systems
- need security decisions after authentication, not only before it
- want IAM policy and AI-assisted risk evaluation in one platform
- want a path from human approval to controlled automation

## Repository Layout

This repository is a multi-module platform, not a single library.
The root build includes:

- `contexa-core`
- `contexa-identity`
- `contexa-iam`
- `contexa-common`
- `contexa-autoconfigure`
- `spring-boot-starter-contexa`

## Practical Notes

- Community use still requires understanding of Spring Security, LLM configuration, and vector store setup.
- `standalone` and `distributed` should be treated as deliberate deployment choices.
- Contexa is not just an AI chat integration. It is an identity, authorization, analysis, and response platform.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

This project is released under Apache License 2.0.
