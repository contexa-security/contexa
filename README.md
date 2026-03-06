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

Contexa adds **AI-powered continuous verification** to your Spring application with two annotations. No code rewrites. No infrastructure changes.

```java
@SpringBootApplication
@EnableAISecurity   // activate AI Zero Trust
public class MyApp { }
```

```java
@Protectable   // this resource is now AI-protected
@DeleteMapping("/api/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}
```

Every request is analyzed through **384-dimensional context vectors**, behavioral pattern matching, and a **2-tier LLM architecture** that delivers real-time autonomous threat detection.

---

## Core Architecture

### Zero Trust Decision Flow

```
Request
  -> HCADFilter (384-dim context vector extraction)
  -> ZeroTrustAccessControlFilter (action enforcement)
  -> CustomDynamicAuthorizationManager (XACML policy evaluation)
```

**5 autonomous actions**: `ALLOW` | `BLOCK` | `CHALLENGE` (MFA) | `ESCALATE` (human review) | `PENDING_ANALYSIS`

### Identity DSL

Fluent security configuration with built-in MFA, XACML, and AI session management:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PlatformConfig platformDslConfig(
            IdentityDslRegistry<HttpSecurity> registry,
            CustomDynamicAuthorizationManager authManager,
            AISessionSecurityContextRepository sessionRepo) {

        return registry
            .global(http -> http
                .authorizeHttpRequests(auth -> auth
                    .anyRequest().access(authManager))
                .securityContext(sc -> sc
                    .securityContextRepository(sessionRepo)))
            .mfa(mfa -> mfa
                .primaryAuthentication(auth -> auth
                    .formLogin(form -> form.defaultSuccessUrl("/dashboard")))
                .passkey(Customizer.withDefaults()))
            .session(Customizer.withDefaults())
            .build();
    }
}
```

Supported authentication methods: `form()` | `rest()` | `ott()` | `passkey()` | `mfa()` (multi-factor)

### Shadow Mode (4-Stage Migration)

| Stage | Mode | Description |
|-------|------|-------------|
| 1 | **Shadow** | AI observes only. No enforcement. Zero risk. |
| 2 | **Advisory** | AI recommends. Human decides. |
| 3 | **Hybrid** | AI blocks clear threats. Human handles edge cases. |
| 4 | **Autonomous** | Full AI security with human oversight. |

Deploy in production on Day 1 with zero risk. Graduate to full autonomy over months.

### 16 AI Labs

Specialized AI engines covering policy generation, risk assessment, behavior analysis, security intelligence, access control optimization, audit compliance, and more. Each lab operates independently with sub-50ms response time.

---

## Quick Start

```gradle
implementation 'io.contexa:spring-boot-starter-contexa:0.1.0'
```

```yaml
# application.yml
contexa:
  infrastructure:
    mode: standalone

spring:
  ai:
    ollama:
      base-url: http://127.0.0.1:11434
      chat:
        options:
          model: qwen2.5:7b
    vectorstore:
      pgvector:
        dimensions: 1536
        distance-type: COSINE_DISTANCE
```

---

## Modules

| Module | Description |
|--------|-------------|
| `contexa-common` | Shared annotations (`@EnableAISecurity`, `@Protectable`), DTOs, enums |
| `contexa-core` | HCAD engine, 2-tier LLM orchestration, vector analysis, Zero Trust filters |
| `contexa-identity` | Identity DSL, MFA flows (form, REST, OTT, passkey), authentication handlers |
| `contexa-iam` | XACML policy engine (PEP/PDP/PIP/PRP), AI-driven dynamic authorization |
| `contexa-autoconfigure` | Spring Boot auto-configuration |
| `spring-boot-starter-contexa` | Starter dependency |

---

## Community vs Enterprise

| | Community (OSS) | Enterprise |
|---|---|---|
| Shadow Mode | Yes | Yes |
| HCAD Detection | Yes | Yes |
| AI Labs (core) | Yes | Yes |
| Identity DSL (MFA) | Yes | Yes |
| SOAR Integration | - | Yes |
| MCP Server (AI Tool Calling) | - | Yes |
| Monitoring (Grafana/Prometheus) | - | Yes |
| Enterprise Dashboard | - | Yes |
| Priority Support | - | Yes |

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
