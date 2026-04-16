# Governance

This document describes the governance model for the open-source CONTEXA core repository.

## Scope

This repository governs the public open-source core:

- runtime control engine
- Spring integration and starter surfaces
- open-source documentation and public trust surfaces
- issue intake, contribution review, and release stewardship

Enterprise operational surfaces are managed separately.

## Governance Model

CONTEXA currently operates under a maintainer-led governance model.

At the current public OSS stage, core maintainers are responsible for:

- architecture direction
- release scope decisions
- issue triage and prioritization
- contribution review and merge decisions
- public security and disclosure coordination
- documentation quality and public positioning

## Review Criteria

Changes are evaluated against the following priorities:

1. runtime security correctness
2. post-authentication control integrity
3. public API and starter stability
4. documentation clarity and operational trustworthiness
5. maintainability and release readiness

## Release Discipline

The public OSS core is versioned and released with semantic versioning in principle.

Each public release should provide:

- versioned change history
- release notes
- current public trust links
- security reporting path
- clear distinction between OSS core and separate enterprise surfaces

## Security Handling

Security issues should follow the reporting path defined in [SECURITY.md](SECURITY.md) and the public `security.txt` surface.

## Public Trust Surfaces

- Main site: https://ctxa.ai
- Demo / verification console: https://demo.ctxa.ai
- Documentation site: https://docs.ctxa.ai
- Public benchmark: https://ctxa.ai/benchmark
- Security policy: [SECURITY.md](SECURITY.md)
- Public security.txt: https://ctxa.ai/.well-known/security.txt