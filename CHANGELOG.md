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

### Added

- `LibraryTableNames` (contexa-common) wraps the `JdbcOperations` handed to the Spring libraries' JDBC classes so that
  they use the prefixed tables; a test reads the libraries' SQL constants and fails when one of them names a table the
  wrapper does not know.
- HOST_OWNED and CONTEXA_OWNED: Contexa's enforcement is the same in both; they differ only in who owns sign-in, session
  and authorization (see the installation guide). HOST_OWNED enforces after the application's own chain, takes no part
  in its sign-in, session, cookie, locale or message bundle, asks for a mail code or a passkey on its own screens, and
  keeps a separate console chain with its own sign-in policy.

### Security

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