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

## AI-Assisted Contributions and Software Governance Policy

CONTEXA embraces AI technologies to accelerate software development and innovation, utilizing AI-assisted workflows within our own core engineering processes. However, to maintain the robustness and security required for enterprise-grade security infrastructure, we apply a strict software quality and supply chain governance policy to all contributions:

1. **Principle of Verification and Responsibility:** Contributors are welcome to utilize AI coding assistants (e.g., GitHub Copilot, ChatGPT) to draft code. However, the final responsibility for the correctness, design patterns, and security of the submitted code rests solely with the human contributor. The contributor must fully understand and be able to explain the mechanics of the submitted patch.
2. **Automated Quality Assurance Standards:** To control the operational overhead of pull request reviews, all submissions must satisfy our automated quality gates. Pull requests must pass all static analysis checks, dependency scanning, and maintain full unit/integration test coverage before they will be queued for manual maintainer review. Unverified or raw AI-generated code that fails automated testing will be automatically rejected.
3. **Supply Chain Security and Licensing:** Contributors must ensure that AI-generated code does not violate third-party intellectual property or copy copyrighted patterns without proper attribution. All contributions require signing the [Contexa Contributor License Agreement (CLA)](https://gist.github.com/contexa73/a038b6d725006372253e3ca9c7cd046d) to ensure clean origin tracing, ensuring the codebase remains safe for commercial, enterprise, and open-source distribution alike.

## Public Project Positioning

When updating public-facing documentation in this repository, keep the project thesis consistent:

- CONTEXA is an open-source AI Native Post-Auth Runtime Control Plane
- CONTEXA is not a vulnerability scanner or binary analysis engine
- CONTEXA complements upstream discovery with downstream runtime controls

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to CONTEXA, you agree that your contributions are subject to the [Contexa Contributor License Agreement (CLA)](https://gist.github.com/contexa73/a038b6d725006372253e3ca9c7cd046d) and licensed under the [Apache License 2.0](LICENSE).