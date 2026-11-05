# Changelog

All notable changes to the open-source CONTEXA core are documented in this file.

The format is based on Keep a Changelog and the project follows semantic versioning in principle.

## [Unreleased]

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

### Added

- `LibraryTableNames` (contexa-common) wraps the `JdbcOperations` handed to the Spring libraries' JDBC classes so that
  they use the prefixed tables; a test reads the libraries' SQL constants and fails when one of them names a table the
  wrapper does not know.
- HOST_OWNED and CONTEXA_OWNED: Contexa's enforcement is the same in both; they differ only in who owns sign-in, session
  and authorization (see the installation guide). HOST_OWNED enforces after the application's own chain, takes no part
  in its sign-in, session, cookie, locale or message bundle, asks for a mail code or a passkey on its own screens, and
  keeps a separate console chain with its own sign-in policy.

### Fixed

- **OAuth2 tokens: the second sign-in of a user no longer fails.** Spring Authorization Server reads the type of its
  columns from the database under the standard table name; under the `ctxa_` name it found none and wrote bytes into the
  text columns, which PostgreSQL keeps in hex form. It now reads the columns of `ctxa_oauth2_authorization`, and a
  table with `bytea` token columns keeps working. The script of the authorization server's tables now creates the same
  `text` columns as the schema. A stored row that cannot be read is removed at the user's next sign-in, which no longer
  fails on it: a person holding such a row signs in again.

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