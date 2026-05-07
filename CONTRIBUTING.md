# Contributing to CONTEXA

Thank you for your interest in contributing to CONTEXA.

This repository contains the open-source core platform. Commercial and enterprise operational surfaces may be developed separately, but contributions to the runtime control engine, shared contracts, Spring integrations, and public OSS experience are welcome here.

## How to Contribute

### Report Bugs

1. Check existing issues first
2. Use the bug report template
3. Include steps to reproduce, expected behavior, and actual behavior
4. Attach logs, screenshots, or stack traces when useful

### Suggest Features

1. Check existing issues for similar requests
2. Use the feature request template
3. Describe the use case, expected behavior, and tradeoffs

### Submit Pull Requests

1. Fork the repository
2. Create a branch from `main`
3. Keep the change focused
4. Add or update tests when needed
5. Run `./gradlew clean compileJava` and `./gradlew test` before submitting
6. Open the pull request against `main`

## Development Setup

### Prerequisites

- Java 17+
- Gradle 8.x via the wrapper
- PostgreSQL 15+
- Docker optional for supporting services

### Build

```bash
git clone https://github.com/contexa-security/contexa.git
cd contexa
./gradlew clean compileJava
```

### Test

Run the full test suite before opening a pull request:

```bash
./gradlew test
```

Run the tests for a single module to iterate faster:

```bash
./gradlew :contexa-iam:test
./gradlew :contexa-core:test
./gradlew :contexa-identity:test
```

Filter to a single test class or method:

```bash
./gradlew :contexa-iam:test --tests '*PolicyEvaluatorTest'
./gradlew :contexa-iam:test --tests '*PolicyEvaluatorTest.someMethod'
```

## Coding Standards

- follow existing code conventions and package structure
- prefer clear, direct names over clever abstractions
- keep changes small and reviewable
- write or update tests for non-trivial behavior changes
- use English for code comments, commit messages, and log messages

## Public Project Positioning

When updating public-facing documentation in this repository, keep the project thesis consistent:

- CONTEXA is an open-source AI Native Post-Auth Runtime Control Plane
- CONTEXA is not a vulnerability scanner or binary analysis engine
- CONTEXA complements upstream discovery with downstream runtime controls

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to CONTEXA, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).