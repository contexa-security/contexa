# Release Notes

## v0.2.0

Release date: 2026-11-27
Release stage: update of the initial public open-source release, with breaking changes listed in the upgrade notes of `CHANGELOG.md`

- the security mode (SANDBOX, FULL) and the ownership (HOST_OWNED, CONTEXA_OWNED) are two settings, and every pair starts with all of CONTEXA's features
- in SANDBOX the decision runs in a servlet filter slot after all of the application's filters
- the application names its user with one contract, `ContexaSubject`: the Spring Security `Authentication`, a `ContexaSubjectResolver` bean or the request attribute `ctxa.subject`; the session, request-attribute and header bridges and the handoff are removed
- the Java style check that runs before every compilation is part of the Gradle build and no longer needs Node.js

## v0.1.1

Release date: 2026-11-02
Release stage: fix release for the initial public open-source release

- IAM seed scripts are read as UTF-8 (Java 17 on Korean Windows and under a POSIX locale)
- first administrator from `contexa.iam.seed.admin.password`, for applications whose sign-in Contexa provides

## v0.1.0

Release date: 2026-04-13
Release stage: initial public open-source release

### Release Scope

This release establishes the public CONTEXA OSS core as an AI-native post-authentication runtime control plane for Spring applications.

### Included in the OSS Core

- request-time runtime zero-trust decisioning
- authenticated human runtime control
- workload and service-client control foundations
- delegated agent execution governance foundations
- Spring Boot starter integration
- public documentation, security policy, and trust surfaces

### Positioning

This release should be evaluated as early-stage security infrastructure rather than mature mass-adoption OSS.
The public scale of the repository is still developing, but the release establishes a clear category position: post-authentication runtime control inside the application layer.

### Public Review Surfaces

- Main site: https://ctxa.ai
- Demo / verification console: https://demo.ctxa.ai
- Documentation site: https://docs.ctxa.ai
- Public benchmark: https://ctxa.ai/benchmark
- Security contact: https://ctxa.ai/.well-known/security.txt

### Related Repository Documents

- [README.md](README.md)
- [CHANGELOG.md](CHANGELOG.md)
- [MAINTAINERS.md](MAINTAINERS.md)
- [GOVERNANCE.md](GOVERNANCE.md)
- [SECURITY.md](SECURITY.md)