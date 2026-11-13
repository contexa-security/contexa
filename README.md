<p align="center">
  <img src="logo.jpg" alt="Contexa" width="400" />
</p>

<p align="center">
  <strong>AI-native runtime security for Spring Boot: decide what a signed-in user may do, request by request.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/></a>
  <a href="https://central.sonatype.com/artifact/ai.ctxa/spring-boot-starter-contexa"><img src="https://img.shields.io/maven-central/v/ai.ctxa/spring-boot-starter-contexa" alt="Maven Central"/></a>
  <a href="https://openjdk.org/"><img src="https://img.shields.io/badge/Java-17%2B-orange.svg" alt="Java 17 or later"/></a>
  <a href="https://spring.io/projects/spring-boot"><img src="https://img.shields.io/badge/Spring%20Boot-3.5-green.svg" alt="Spring Boot 3.5"/></a>
</p>

## What is Contexa?

A login proves who someone is. A role says what they may access. Neither tells you whether the person using the account is its owner doing their own work, or someone who stole the account, or an insider using a legitimate permission for another purpose.

Contexa is an open-source Spring Boot library that closes this gap. For each request to a protected method, it asks an AI model whether the account's owner is doing their own work right now. It weighs the session so far, how the request differs from the user's usual behavior, company records and earlier decisions. It stores the answer as a **decision** and applies it to that user's requests: let them continue, ask for another verification, or stop them.

- **Added to an application you already have.** Your login and your roles stay as they are. Contexa adds one dependency, one annotation and `@Protectable` on the methods to protect.
- **No policy rules to write for the decision.** The AI model chooses the action from the facts of the request; your authorization policies still apply.
- **Out of the request path while nothing changes.** By default the model runs after the response has been sent, so the user does not wait for it; the decision applies from the user's next request. Only a method that asks for the decision inside the call (`@Protectable(sync = true)`) waits for it.
- **Explainable.** Every decision is written to a hash-chained, signed audit record, and for a sample of the model's decisions the exact prompt it received is sealed as evidence for later review.
- **Covers AI agents.** Requests from agents are told apart from people's requests and decided separately.

### The same permission, three outcomes

An employee is allowed to read settlement documents. The login and the role are the same in each case:

| What happens | What Contexa weighs | Decision |
|---|---|---|
| Reads the records of an assigned settlement task | Fits the task and the user's recent activity | `ALLOW` |
| Starts opening unrelated customer records | Behavior differs from the user's usual work | `CHALLENGE`: asks for MFA again |
| Keeps going after failing the check | Evidence of continued misuse | `BLOCK`: stopped until an administrator releases it |

The scenario is illustrative: the decision always depends on the context that is supplied, the configured policies, the model's analysis and the enforcement mode.

## The five decisions

| Decision | Meaning | HTTP status | Valid for |
|---|---|---|---|
| `ALLOW` | Continue as usual | 200 | 15 min (`contexa.security.zerotrust.allow-validity`), then back to pending analysis |
| `CHALLENGE` | Step-up authentication (MFA) is required | 401 | 30 min, or until MFA is passed |
| `ESCALATE` | Held for review while the analysis settles | 423 | 5 min |
| `BLOCK` | Refused until an administrator releases it | 403 | Until released |
| `PENDING_ANALYSIS` | No decision stored yet: the request goes on and is analyzed | request passes | Until a decision is stored |

The table shows the behavior when enforcement is on. The stricter decision wins: a weaker new decision is not stored while a stricter one is in force. Agent requests and `@Protectable(sync = true)` calls are decided on the spot and are refused with 503 when no decision can be obtained.

## How it works

```mermaid
flowchart LR
    A[Signed-in request] --> B[Apply the stored decision]
    B -->|allowed| C[Your protected method]
    B -->|CHALLENGE, ESCALATE or BLOCK| X[Verification or refusal]
    C -. analysis event .-> D[AI analysis:<br/>session, behavior, records, history]
    D --> E[Decision and audit evidence]
    E --> F[(Decision store)]
    F -. read on the next request .-> B
```

The request path only reads the stored decision; it never calls the model. The analysis runs separately, one user session at a time, and the two meet only at the decision store. Analysis is triggered by `@Protectable` calls and by MFA sign-in; an ordinary URL request that is not a protected method is not analyzed. Read [How Contexa Works](https://docs.ctxa.ai/en/docs/reference/architecture/overview.html) for the details.

## Get started

**You need:** Java 17+, Spring Boot **3.5.x** (older versions do not start, and 4.x is not supported; neither are Spring AOT processing and native images), a PostgreSQL database with the pgvector extension that is dedicated to Contexa, and an AI model for chat and for embeddings: a local [Ollama](https://ollama.com), or OpenAI. Anthropic can serve chat, with OpenAI or Ollama for the embeddings.

### Fastest: the CLI

In your Spring Boot project (or an empty folder, which gets a sample application):

```bash
curl -fsSL https://install.ctxa.ai/install.sh | sh      # Windows: irm https://install.ctxa.ai/install.ps1 | iex
contexa init
```

[`contexa init`](https://github.com/contexa-security/contexa-cli) asks which AI model to use, prepares a local PostgreSQL with pgvector and the model, adds the dependencies, `@EnableAISecurity` and the settings to your project, checks that everything resolves, and offers to start the application. `contexa reset` undoes it.

### By hand

**1. Add the dependencies.** The starter brings the five Contexa modules; add Spring Security and the Spring AI model and vector-store starters you use next to it. The starter does not bring Spring Security, so that adding it alone changes nothing in your application.

```gradle
dependencies {
    implementation 'ai.ctxa:spring-boot-starter-contexa:0.1.1'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation platform('org.springframework.ai:spring-ai-bom:1.1.8')
    implementation 'org.springframework.ai:spring-ai-starter-model-ollama'
    implementation 'org.springframework.ai:spring-ai-starter-vector-store-pgvector'
}
```

<details>
<summary>Maven</summary>

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.ai</groupId>
            <artifactId>spring-ai-bom</artifactId>
            <version>1.1.8</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
<dependencies>
    <dependency>
        <groupId>ai.ctxa</groupId>
        <artifactId>spring-boot-starter-contexa</artifactId>
        <version>0.1.1</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.ai</groupId>
        <artifactId>spring-ai-starter-model-ollama</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.ai</groupId>
        <artifactId>spring-ai-starter-vector-store-pgvector</artifactId>
    </dependency>
</dependencies>
```

</details>

**2. Turn Contexa on.** With only the dependency, Contexa stays off and your application runs as before. The annotation turns it on; without a mode your application keeps its own sign-in.

```java
@SpringBootApplication
@EnableAISecurity   // io.contexa.contexacommon.annotation.EnableAISecurity
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

**3. Configure.** Contexa needs a database of its own (it creates its tables there at the first start) and an AI model. Pull the Ollama models first: `ollama pull qwen3:8b` and `ollama pull mxbai-embed-large`.

```yaml
contexa:
  security:
    zerotrust:
      mode: SHADOW             # analyze and record decisions without applying them
  datasource:                  # the dedicated Contexa database, not your application's
    url: jdbc:postgresql://localhost:5432/contexa
    username: contexa
    password: ${CONTEXA_DB_PASSWORD}
  llm:
    selection:
      chat:
        mode: dynamic-priority
        priority: ollama
      embedding:
        mode: fixed
        priority: ollama
    chat:
      ollama:
        base-url: http://127.0.0.1:11434
```

**4. Protect a method.**

```java
@Service
public class OrderService {

    @Protectable   // io.contexa.contexacommon.annotation.Protectable
    public Order getOrder(Long orderId) {
        return orderRepository.findById(orderId).orElseThrow();
    }
}
```

A signed-in user (a Spring `Authentication`) is needed when the method is called under `SHADOW` and `ENFORCE`; without one the call is refused with an `AccessDeniedException`. Run the application, call the method as a signed-in user, and look for `[IamSeedData] OSS schema provenance verified.` in the startup log. With Spring Boot Actuator, `GET /actuator/contexacapabilities` shows which parts are ready. Details: [Getting started](https://docs.ctxa.ai/en/get-started.html).

### First sign-in and one-time codes (where Contexa provides the sign-in)

- **First sign-in:** a first start on a database without user accounts adds sample accounts (`admin`, `manager`, `developer`, `user`, `finance`, all with the password `1111`) and says so in the start log. Sign in at `/contexa/admin/login` as `admin` / `1111` and change the password with "Change password" in the console header.
- **Development:** with a `local`, `dev`, `development` or `test` profile, or without a mail server, the one-time code of the second step is written to the start log as `[OTT] Sign-in code for ...`, and the code pages say so. Nothing has to be set up. The local mail inbox (Mailpit) the CLI prepares receives the same code (SMTP `127.0.0.1:51025`, mails at http://127.0.0.1:58025).
- **Production:** start without those profiles and set `spring.mail.*` to your mail server (host, port, username, password, and `spring.mail.properties.mail.smtp.auth` / `starttls.enable` as it asks). Codes then go by mail only. The start log says `One-time sign-in codes are mailed through host:port`, or what is wrong and what to set. `contexa.auth.ott.code-to-console=false` makes sure no code is written to the log.

## Choose the modes

Three independent settings decide how Contexa runs:

| Setting | Options | What it decides |
|---|---|---|
| Sign-in ownership | `SANDBOX` (default) / `FULL` | Your application keeps sign-in, or Contexa provides sign-in, MFA and the admin console (`@EnableAISecurity(mode = SecurityMode.FULL)`) |
| Enforcement, `contexa.security.zerotrust.mode` | `SHADOW` / `ENFORCE` (default) / `OBSERVE` / `DISABLED` | `SHADOW` analyzes and records only; `ENFORCE` stores and applies decisions |
| Infrastructure, `contexa.infrastructure.mode` | `standalone` (default) / `distributed` | State in memory of one server, or shared through Redis and Kafka. `distributed` needs a single Redis server or Sentinel: Redis Cluster is not supported in this release. `org.redisson:redisson` brings a JCache provider, so an application whose cache goes through JCache sets its cache, for example `spring.cache.type=caffeine`, or names its own provider, for example `spring.cache.jcache.provider=org.ehcache.jsr107.EhcacheCachingProvider` |

**Start with `SHADOW`.** Watch the decisions for your own scenarios, then switch to `ENFORCE`. See [Start Safely with Enforcement Modes](https://docs.ctxa.ai/en/docs/install/shadow-mode.html).

## What Contexa adds to your JVM

Contexa runs in your application's JVM, so what it holds is yours to size. These figures were measured on one machine (20 cores, `-Xmx1g`, a small Spring Boot application, PostgreSQL, Redis and Kafka), with the same application with and without Contexa:

| | Without Contexa | With Contexa |
|---|---|---|
| One signed-in user, a few calls (heap in use after a full collection) | 65 MB | 154 MB |
| Process memory (RSS) in that state | 795 MB | 1,123 MB |
| 1,000 people at once for two rounds, the model deciding: heap in use after a full collection | 97 MB | about 530 MB |
| Threads, after that load has ended and a minute has passed | 197 | about 380 |

- **What the heap holds under load:** a heap dump of that state held about 340 MB of live objects (the 530 MB above is the JVM's own count, which rounds up by region and includes the buffers below). Contexa's own part is the decisions waiting for the model (about 10 KB for each event), the prompt and context caches, and the records Contexa keeps for its decisions, about 80 to 100 MB in all. Each of these stores has a limit in bytes that follows the maximum heap (`-Xmx`), so none grows without bound; the limits are the share Contexa may use, and a store that is full drops its oldest entries.
- **Netty buffers:** the clients Contexa brings (WebClient, Lettuce, Redisson) allocate from Netty's default pool, which holds a 4 MB chunk for each arena in use and has twice as many arenas as cores. On the 20-core machine above that was 64 MB of heap and, estimated, 96 MB of direct memory; it is smaller on a smaller machine. It is shared by every Netty client in the JVM, so Contexa does not change it. On a server with many cores you can lower it with `-Dio.netty.allocator.numHeapArenas=4 -Dio.netty.allocator.numDirectArenas=4`: with 4 arenas on the machine above, process memory fell by 183 MB and the heap by 107 MB, and response times, errors and decisions did not change (one run of each).
- **Threads:** Contexa's pools start threads when they have work and give them back after a minute without any. The analysis pool is 64 threads by default (`contexa.security.plane.agent.analysis-stripes`), as many as the analysis threads can use. Contexa's own HTTP clients and its reactive time limits have two threads each (`contexa-ai-*`, `contexa-timer-*`), started at the first call and ended when the application closes; they do not use the JVM's shared `reactor-http-nio` and `parallel` threads. A chat or embedding model you configure under `spring.ai.*` uses the HTTP client Spring AI builds for it.

## How fast decisions are made

Decisions are made by your model, so how long a burst of new sessions waits for its first decisions depends on the model server, not on Contexa. Your application does not wait for them: no call waits for a decision, except `@Protectable(sync = true)`.

- **The speed** is the calls the model server takes at once divided by the time of one call. A decision makes at least one chat call, two in the runs below with the local model, and up to six when the first layer hands the request to the second. `contexa.llm.gate.remote-max-concurrent` (default 16) is the calls at once on a remote provider, and `contexa.llm.gate.self-hosted-max-concurrent` (default 2) on a self-hosted server such as Ollama: set the second to the parallel requests your server runs (`OLLAMA_NUM_PARALLEL`).
- **While decisions wait** they keep their order and the first decision of a session goes first; a repeat of a request whose decision is already in line adds none (a request from another address or browser is a new question and is decided). The analyses that run at once follow what the model server serves within the event budget (`contexa.security.plane.agent.event-timeout-ms`, 180 s), from the measured time of its chat calls, so an analysis does not fail by waiting for the server. `contexa.security.plane.agent.analysis-stripes` (default 64) is the most that run at once.
- **Measured**, with 1,000 users who sign in at once and make three protected calls each (one machine with 20 cores, `-Xmx1g`, an ALLOW valid for 15 minutes): Claude Haiku 5.5 (16 calls at once) made all 1,001 decisions about three and a half minutes after the first request. A local qwen3:8b on one 8 GB GPU (2 calls at once, about 12 s a call and two calls a decision) makes about 3.4 decisions a minute: 100 users were decided in 26 minutes, and 1,000 users in 4 hours 51 minutes. The application answered every request in both cases, and the decisions that waited stayed in order.
- **A slow model fills the line, not your application.** When decisions arrive faster than the model makes them, the log says that an analysis did not end within the limit of its commit (`DecidedRecordAcknowledger`), and a vector search that waits for a slow embedding model gives up and the analysis goes on without it. Size the model server for the sessions you expect to start at once, or accept the wait.

## Documentation and examples

- **Documentation:** [docs.ctxa.ai](https://docs.ctxa.ai): [Getting started](https://docs.ctxa.ai/en/get-started.html), [How Contexa Works](https://docs.ctxa.ai/en/docs/reference/architecture/overview.html), [Configuration](https://docs.ctxa.ai/en/docs/install/configuration.html), [`@Protectable` reference](https://docs.ctxa.ai/en/docs/reference/iam/protectable.html).

Runnable applications in [contexa-examples](https://github.com/contexa73/contexa-examples), described in the [Examples Guide](https://docs.ctxa.ai/en/docs/install/examples.html):

| Example | What it shows |
|---|---|
| `contexa-example-quickstart` | The smallest setup |
| `contexa-example-protectable` | Four ways to use `@Protectable` |
| `contexa-example-identity-dsl` | The authentication DSL |
| `contexa-example-identity-mfa`, `-mfa-multi` | MFA with custom pages, and two MFA flows |
| `contexa-example-identity-oauth2` | OAuth2 stateless authentication |
| `contexa-example-legacy-system` | Adding Contexa to an existing login |

## Modules

| Module | Responsibility |
|---|---|
| `spring-boot-starter-contexa` | The one dependency an application adds |
| `contexa-autoconfigure` | Spring Boot auto-configuration and wiring |
| `contexa-core` | The decision engine: AI calls, analysis, learning, sealed evidence, audit |
| `contexa-identity` | Sign-in flows, MFA and passkeys, OAuth2, request-time filters |
| `contexa-iam` | Policy-based authorization, `@Protectable`, the admin console |
| `contexa-common` | Decision types, shared annotations, the authentication bridge |

These modules are the open-source runtime. Commercial and enterprise operational features are delivered separately.

## Project

Contexa is at an early stage (`0.1.x`) and licensed under [Apache 2.0](LICENSE).

- **Contribute:** [Contributing guide](CONTRIBUTING.md), [issues](https://github.com/contexa-security/contexa/issues), [maintainers](MAINTAINERS.md), [governance](GOVERNANCE.md), [code of conduct](CODE_OF_CONDUCT.md).
- **Report a vulnerability:** follow [SECURITY.md](SECURITY.md).
- **History:** [Changelog](CHANGELOG.md), [release notes](RELEASE_NOTES.md).
