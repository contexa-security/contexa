# Contributing to Contexa

Thank you for your interest in contributing to Contexa! This guide will help you get started.

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/contexa-security/contexa/issues) to avoid duplicates
2. Use the [Bug Report template](https://github.com/contexa-security/contexa/issues/new?template=bug_report.md)
3. Include steps to reproduce, expected behavior, and actual behavior
4. Attach logs, screenshots, or stack traces if applicable

### Suggesting Features

1. Check [existing issues](https://github.com/contexa-security/contexa/issues) for similar requests
2. Use the [Feature Request template](https://github.com/contexa-security/contexa/issues/new?template=feature_request.md)
3. Describe the use case and expected behavior

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch from `main`: `git checkout -b feature/your-feature`
3. Make your changes following the coding standards below
4. Write or update tests as needed
5. Run `./gradlew clean compileJava` to verify the build
6. Commit with a clear message describing the change
7. Push and open a Pull Request against `main`

## Development Setup

### Prerequisites

- Java 21+
- Gradle 8.x (wrapper included)
- PostgreSQL 15+
- Docker (optional, for infrastructure services)

### Build

```bash
git clone https://github.com/contexa-security/contexa.git
cd contexa
./gradlew clean compileJava
```

## Coding Standards

- Follow existing code conventions and patterns in the project
- Use Java 21 features where appropriate
- Write meaningful commit messages
- Keep pull requests focused on a single change
- All comments and log messages must be in English

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing to Contexa, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
