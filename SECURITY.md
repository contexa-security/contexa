# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in Contexa, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: **security@contexa.io**
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix & Disclosure**: Coordinated with reporter

### What to Expect

- We will acknowledge receipt of your report
- We will provide an estimated timeline for a fix
- We will notify you when the vulnerability is fixed
- We will credit you in the release notes (unless you prefer anonymity)

## Security Best Practices

When using Contexa in production:

- Keep Contexa updated to the latest version
- Use environment variables for sensitive configuration (API keys, credentials)
- Enable TLS for all network communication
- Follow the principle of least privilege for IAM policies
- Regularly review and rotate credentials
