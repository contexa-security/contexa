# Changelog

All notable changes to the open-source CONTEXA core are documented in this file.

The format is based on Keep a Changelog and the project follows semantic versioning in principle.

## [Unreleased]

### Security

- **The code the victim passes no longer frees the attacker's session.** A CHALLENGE is answered per session: the
  session that passed the code goes on, and every other session of the user stays stopped until it answers for itself
  or the CHALLENGE would have lapsed. A user on several devices verifies on each. An administrator's override ends it.
- **A stolen password no longer registers a passkey.** A passkey answers a CHALLENGE, so registering one now needs a
  confirmed user. Under `HOST_OWNED`: a code mailed to the user's own address, or the application's own MFA sign-in in
  the last five minutes. Under `CONTEXA_OWNED`: a session that completed MFA; any other verifies first and comes back.
  A CHALLENGE is answered first, and a BLOCK or an ESCALATE refuses it.
- **Logging out ends the sign-in it left waiting for a code.** With the Redis store the `MFA_SID` cookie and the code could
  finish it from another browser. A session that ends, by logout or otherwise, now ends the MFA flow it started, in both
  stores.
- **Every spelling of a name meets the decision of that name.** A BLOCK of `plain-k9` also stops `PLAIN-K9` and a
  full-width spelling. If names of your application differ by case alone, set
  `contexa.security.zerotrust.normalize-user-keys=false`: with it on, a restriction of one reaches the other. A BLOCK
  stored by an earlier version stays in force; other decisions under a name with capitals start again after the upgrade.

### Fixed

- **A store outage is no longer an outage of the application.** Redis or Contexa's database that stops, freezes or runs out
  of connections used to hold every request of a signed-in user, the pages no decision protects included: a minute for each
  read on Redis, and a minute on the pool. A request now waits about a second once and then not at all, and everything
  comes back by itself. The application's own Redis client and pool settings are not touched, and the engine's threads keep
  their waits. While a store is away a protected call goes on as the operating mode specifies, and the interval is written
  to the log and the audit log as calls without a decision.
- **A restriction outlives the outage.** A BLOCK, CHALLENGE or ESCALATE this server read stays in force while Redis does not
  answer, and a BLOCK this server never read is found in `ctxa_blocked_user`.
- **A technical failure is no denial.** An authorization check that did not finish is recorded as `UNKNOWN`, not `DENY`, so
  an outage no longer ends in a permanent BLOCK of normal users.
- **Authenticated Kafka works.** Contexa's clients take `spring.kafka.security.*`, `ssl.*`, `properties.*` and SSL bundles as
  Spring Boot does; what Contexa's delivery depends on stays Contexa's.
- A start that Redisson's JCache provider stopped says why and names `spring.cache.type=caffeine`.
- The start names Redis Cluster at ERROR, which this release does not support, and, in standalone, that a restart ends a
  BLOCK and a CHALLENGE in force.
- **No request reads as undecided while an ended ESCALATE is being replaced.** Concurrent readers of an ESCALATE past its
  time could answer PENDING_ANALYSIS: one found no analysis, another wrote the replacement, and the first then met the
  new last-verified record. The replacement now answers them too, in both repositories.
- **`@EnableAISecurity` can stand on any configuration class.** Declared on the class that also declares the application's
  `PlatformConfig`, or on one parsed before it, the application stopped at start with two `PlatformConfig` beans. The
  application's configuration classes are now parsed first, so every conditional bean of Contexa's configuration gives way
  to the application's wherever that is declared. Contexa's values reach the `Environment` after those classes are parsed
  and before the auto-configurations.
- **A decision at a protected method is answered by Contexa whatever exception handlers the application has.** A catch-all
  `@ExceptionHandler(Exception.class)` at the top order turned a CHALLENGE into its own answer and ended a BLOCK with a
  broken connection. `ZeroTrustEnforcementExceptionResolver` now answers Contexa's own exceptions ahead of every advice, of
  a handler inside a controller and of an application's resolver. The answer is always JSON, in Contexa's field names; every
  other exception stays the application's.
- **A `@Protectable` method runs in `@Scheduled` and `@Async` work.** A call on a thread that holds neither a user nor a
  request failed with `AuthenticationCredentialsNotFoundException`. There is no one to decide for, so it now runs: the first
  run of each method writes a warning, and `ctxa_ai_security_llm_trigger_suppression` keeps a `RAN_WITHOUT_USER` row a minute
  per method with the calls counted. A user carried into the thread is decided, and a request with no user stays refused.
- **A live session id no longer leaves the running application.** The sealed evidence, the audit log, the decision
  observations, the vector store and the model's input name a session by a reference (`sid-` and 24 hex digits of its
  SHA-256): two records of one session carry the same reference, and the reference signs nobody in. The session stores
  and the event a node hands to another keep the id, since they are keyed by it. Rows already stored stay as they are.
  The `session_id` of the audit log and the observations is now that reference, so it cannot be matched to a live
  session: `ctxa_active_sessions` and the session store still hold the id.
- A query string keeps the names of its parameters, not their values (`pin&newPwd`): in the sealed evidence, the decision
  observations and the session's records. A part without `=` is left out, since it may be the value itself. The model's
  input never held a query.
- **A sealed package changed without the signing key no longer passes the re-inspection.** Where the installation signs,
  a package without the signature it should carry fails instead of reading as not verifiable, whatever schema it names:
  a decision changed, its schema lowered and its hash computed again used to pass in full. Packages captured before the
  oldest signed package kept are the ones sealed before a key existed and stay as they were. Run a re-inspection after
  this version to read the packages already kept: the inspector version moves to 28.
- The re-inspection follows `previous_package_hash`: the package after one that was removed fails, naming the hash that
  is gone. A package the retention may have taken (older than the shorter of `retention.period` and
  `retention.clean-period`) is no finding. The limits of the seal are in `SECURITY.md`.
- The console's version comparison and shadow pairs read the sealed decision, which the package hash covers, not the
  `decision_jsonb` copy beside it.
- **A layer model set in `contexa.security.tiered.llm.layer1.model` or `layer2.model` runs with Anthropic from the
  settings alone.** The second layer used to run on the first layer's model without a word, and one chat model bean of
  the second layer's model pulled the first layer onto it too. Each layer's model is now made from the Anthropic chat
  model, with the same client and default options of its own, so a model that refuses sampling values is not sent the
  defaults of another one. No chat model bean of your own is needed.
- A layer model that cannot be made (no `contexa.llm.bindings.chat` binding and a provider other than OpenAI or
  Anthropic, or another provider's model id on Anthropic) is told at the start in one ERROR line: the layer, the model
  set and the model that runs in its place. The application starts as it did. A wrong model id of the same provider
  cannot be told without a paid call and fails at the first call of that layer.
- A decision record names the model that answered, else the model that was asked. A decision that never reached a
  model (`QUEUE_TIMEOUT`, `REJECTED_BACKPRESSURE`) names none; it used to name the configured model.
- **Contexa no longer fills the application's heap under load (PR-91).** Every request kept a snapshot of its session
  for 30 minutes after its decision, each with up to a hundred decoded decisions, so 10,000 requests took hundreds of
  megabytes and a 384 MB application stopped with `OutOfMemoryError` after about 1,500 decisions, in both infrastructure
  modes. What the requests hold now has a limit in bytes, a twentieth of the maximum heap between 16 MiB and 256 MiB: past
  it the committed requests give up their snapshots first, the longest committed first, and their committed mark stays,
  so nothing is recorded twice. A request no analysis reaches keeps only that mark. Nothing a decision reads changes: the
  session's history and the prompt are as they were. A later resolution of a request whose snapshot went reads the
  session again.
- The other per-decision places on the heap have a limit in bytes as well: the canonical contexts kept while a prompt is
  built (a thirty-second of the heap) and the documents of the cached vector searches (a thirty-second of the heap,
  beside `contexa.security.tiered.vector-cache.max-size`, which still holds); a search or a context not kept is resolved
  again to the same result. The prompt snapshots waiting for their sealing are held within a twentieth of the heap, the
  oldest going first. The event collectors keep the id and time of the recent events, not the events with their whole
  context. An AI operation that fails or streams to its end no longer leaves its audit entry in memory.
- **What an administrator changes reaches the sessions that are open.** Disabling a user ends the user's sessions at once,
  and a change of groups, roles, permissions or the role hierarchy is read again by each open session on its next request.
  A bearer token keeps the rights it was issued with until it expires; disabling the account ends it.
- **The console's administrator is not the application's user of that name** under `HOST_OWNED`: a BLOCK of one no longer
  locks the console of the other, in either direction, and the block list stays open to a console session.
- **Behind a proxy nobody named, one person's typing no longer stops everyone.** When requests carry `X-Forwarded-For` and
  `contexa.security.tiered.security.trusted-proxies` is empty, the address limit of sign-ins is not applied and an ERROR
  names the setting. The lock of each account works as before. **Set the setting if you run behind a proxy**: until you do,
  no address limit applies, and a client that adds the header itself escapes it too.
- **A user can answer a CHALLENGE in `contexa.infrastructure.mode=distributed` whatever the sign-in is made of.** An MFA
  flow stored in Redis could not be read back when the sign-in held a read-only collection (a one-time token or a
  remember-me sign-in with Contexa's user or Spring's `User`, a JWT, an OAuth2 login) or an object the reading node
  cannot load, and the user could not go on. A stored flow now keeps of a sign-in of any kind only what the flow reads:
  the name, the authorities, whether it is authenticated and the facts of the login. The principal, the credentials and
  the application's classes no longer reach Redis, and a stored flow keeps the login's method and time as the in-memory
  flow does. An attribute that cannot be stored or read back (a value of the application's policy) is left out with an
  error in the log, and the rest of the flow stays.
- A stored flow that cannot be read now stops the request and stays as it is. It used to be replaced by the copy the
  request held, without the version check.
- A request running beside a write no longer finds no flow in Redis and ends it.
- Flows in progress in Redis when this version starts cannot be read and start again: the stored form changed.

### Added

- **A way out for a user with neither a mail address nor a passkey.** An application tells a user's address with a
  `BridgeUserEmailProvider` bean. An administrator can enter the address on the user's page, or release a CHALLENGE on the
  block list; the release is recorded in the audit and nothing is learned from it. The user who passes a code is offered
  a passkey at once, and `/contexa/step-up` is the page to link from your account menu. The start log and the console's user
  list say how many users could not answer a CHALLENGE.

### Changed

- **Every database object Contexa creates starts with `ctxa_`**: tables, views, sequences, indexes and named
  constraints (`users` is now `ctxa_users`, `contexa_schema_provenance` is `ctxa_schema_provenance`). A table of your
  application with a plain name (`users`, `role`, `audit_log`, ...) is never read, changed or renamed, even in the same
  database. The tables Spring Security and Spring Authorization Server fix in their own SQL (`one_time_tokens`,
  `user_credentials`, `user_entities`, `oauth2_*`) are used under the prefix too, ShedLock's table is `ctxa_shedlock`,
  and the vector store's default table is `ctxa_vector_store` (its index `ctxa_vector_store_index`, the name Spring AI
  looks for).
- **An existing Contexa database is moved automatically**, in one transaction, when the data source is created, before
  any bean reads from it: tables, sequences, indexes, constraints and the recorded ownership of the tables follow, and
  data and sequence positions stay as they were. Only a database that has all of Contexa's marker tables under the old
  names is moved; if only some of them exist, they are taken for the application's own and left as they are, and if
  both names exist for a table the start stops without changing anything. Nodes that start together are safe (one
  moves the database under a database lock, the others wait and find it moved), but a node of the earlier version
  cannot run against a moved database: stop every node of the earlier version before the first node of this version
  starts, and keep a backup as for any upgrade.
- `spring.ai.vectorstore.pgvector.table-name` and `contexa.rag.etl.vector-table-name` default to `ctxa_vector_store`; a
  configuration that names `vector_store` explicitly points at a table Contexa no longer creates.
- **A failed Layer 2 call no longer ends in a BLOCK.** With `contexa.security.tiered.layer2.allow-escalate-final-action`
  off (the default) a model error or a time-out at Layer 2 ends as `layer2.escalate-fallback-action` (CHALLENGE by
  default, answered with 401) instead of 423 and, five minutes later, a BLOCK of a user no model judged. A CHALLENGE or
  BLOCK the model already decided stands when a step after it fails. An ESCALATE an earlier version left in the store
  ends as the same action when it is read, so nothing is promoted any more; a BLOCK promoted before the upgrade stays
  until it is released. With the setting on, the 423, the analysis-pending screen and the promotion stay as they were.
- **The address limit of the login policy now stops a password sign-in**, including the right password, until its block
  runs out. Its address follows the rule of every other decision: a forwarded header counts only from a proxy listed in
  `contexa.security.tiered.security.trusted-proxies` (or from `server.forward-headers-strategy`). **Behind a proxy that
  is not listed, all users arrive from its address and share one limit, so list it before you upgrade**; the log names
  the setting when such an address is blocked. Behind a listed proxy `X-Forwarded-For` is read from its end, past the
  listed proxies: list every proxy of the chain, a CDN included. `ClientIpResolver` in
  `io.contexa.contexacommon.security`, which believed any header, is gone; use `SessionFingerprintUtil.extractClientIp`.
- **A decision steps aside only for Contexa's own paths.** `/logout-report`, `/logout/report` and any path that only
  starts like one of Contexa's are the application's and meet the decision, and so do `/mfa/*`, `/api/mfa/*`, `/webauthn/*`
  and `/.well-known/*` beyond the paths the running flows and Contexa's discovery documents name. A path with a dot
  segment, an encoded character, a path parameter or a backslash never counts as Contexa's.
- The console's resource scan covers the application's own packages beside the configured ones.
- **A request decided in place no longer passes under a stricter decision stored meanwhile.** When a CHALLENGE, an
  ESCALATE or a BLOCK is stored for the user while another of the user's calls is being decided, that call is answered
  with the stored decision, whichever session it came from, in memory and on Redis alike. The audit record of the call
  keeps the decision of its analysis, marked as kept out where the agent decision record shows it. A CHALLENGE an agent's
  accountable person confirmed, a shadow boundary and an ALLOW of another session change nothing.
- **A user's password hash no longer reaches the caches.** The copies of a user the access decisions keep in the memory
  cache and in Redis (`contexa:cache:user_details:<id>`, `contexa:cache:user_details_name:<name>`) hold no `password`
  field, and `Users` leaves it out of JSON everywhere. Copies an earlier version wrote are read without it and taken out
  of the store at every start; while old nodes run they can write such copies again, and the last node to start takes
  those out. `AuthorizationContext.subjectEntity().getPassword()` is empty on a cached copy; nothing in Contexa reads it.

### Added

- `LibraryTableNames` (contexa-common) wraps the `JdbcOperations` handed to the Spring libraries' JDBC classes so that
  they use the prefixed tables; a test reads the libraries' SQL constants and fails when one of them names a table the
  wrapper does not know.
- HOST_OWNED and CONTEXA_OWNED: Contexa's enforcement is the same in both; they differ only in who owns sign-in, session
  and authorization (see the installation guide). HOST_OWNED enforces after the application's own chain, takes no part
  in its sign-in, session, cookie, locale or message bundle, asks for a mail code or a passkey on its own screens, and
  keeps a separate console chain with its own sign-in policy.

### Security

- **A BLOCK cuts a response that started under an ALLOW too.** Only a response started while the analysis was pending
  could be cut, so a stream begun in the 15 seconds an ALLOW lasts ran to its end past the BLOCK. Every response of a
  signed-in user under ENFORCE can now be cut, and carries `X-Contexa-Monitored` and `X-Contexa-Blocked-Redirect` unless
  `contexa.security.zerotrust.monitoring-headers=false`. What cuts a response stays a BLOCK received after it started.
- **The screens of a decision only lead to paths of the application**: `returnUrl` of
  `/contexa/zero-trust/analysis-pending` went to the browser unchecked, and `mfaUrl` of
  `/contexa/zero-trust/challenge-required` let a backslash, a tab or an encoded slash through. Anything but a path of the
  application, however it is encoded, now falls back to the screen's own destination.
- **A sign-in no longer tells who has an account**: the single-factor flows answer every refused sign-in with
  `Invalid username or password.`, as the MFA flows do, instead of `User not found: <name>`, `Invalid password` or
  `Account is locked`. A refused sign-in also costs one password comparison whether the account exists or not, so the
  time of the answer tells nothing either.
- **An attempt during a lock no longer moves the lock's end**: trying a locked account, even with the right password,
  pushed `lock_expires_at` back, so that anyone could keep the account locked. The count of failures still starts over
  when the lock has run out.
### Fixed

- **OAuth2 tokens: the second sign-in of a user no longer fails.** Spring Authorization Server reads the type of its
  columns from the database under the standard table name; under the `ctxa_` name it found none and wrote bytes into the
  text columns, which PostgreSQL keeps in hex form. It now reads the columns of `ctxa_oauth2_authorization`, and a
  table with `bytea` token columns keeps working. The script of the authorization server's tables now creates the same
  `text` columns as the schema. A stored row that cannot be read is removed at the user's next sign-in, which no longer
  fails on it: a person holding such a row signs in again.
- **OAuth2 tokens: the server accepts the tokens it issues.** Spring Boot's settings bean, which has no issuer, took the
  place of Contexa's, so `contexa.auth.oauth2.issuer-uri` reached the decoder and not the chain, and a token named the
  path of the login as its issuer. The chain now issues under the issuer of the settings or, when they name none, under
  `contexa.auth.oauth2.issuer-uri` (default `http://localhost:9000`), the rule the decoder already had. Set the key to
  the public address of the application.

## [0.1.1] - 2026-11-02

### Fixed

- The IAM seed scripts are read as UTF-8, like the schema. Java 17 takes its default charset from the operating
  system, so the Korean seed data was stored garbled on Korean Windows (MS949) and the startup failed on a unique
  constraint under a POSIX locale.

### Added

- `contexa.iam.seed.admin.password` (with `.username`, default `admin`, and `.email`, default `admin@localhost`)
  creates one administrator in the system administrators group at the start. An existing user with that name or
  e-mail is never changed, so a password changed in the admin console stays. Without the password nothing is created.

## [0.1.0] - 2026-04-13

### Added

- Open-source AI Native Post-Auth Runtime Control Plane baseline for Spring applications
- Runtime behavioral analysis and zero-trust control flow inside the application layer
- Request-time control actions including `ALLOW`, `CHALLENGE`, `BLOCK`, `ESCALATE`, and `PENDING_ANALYSIS`
- Identity, IAM, and AI runtime modules packaged as a coherent open-source core
- Spring Boot starter for simplified adoption
- Public security policy, contributing guide, code of conduct, issue templates, and CI workflow

### Clarified

- CONTEXA open-source core positioning as a downstream runtime control layer
- Relationship between the open-source core and separate enterprise operational surfaces
- Public links for documentation, benchmark entry, and security contact