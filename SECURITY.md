# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in CONTEXA, report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email `security@contexa.io`
2. Include:
   - a clear description of the issue
   - reproduction steps
   - potential impact
   - any suggested mitigation or fix

### Public Security Contact

The public RFC 9116 contact file is published at:

- `https://ctxa.ai/.well-known/security.txt`

### Response Timeline

- acknowledgment within 48 hours
- initial assessment within 5 business days
- coordinated disclosure timing with the reporter

### What to Expect

- confirmation that the report was received
- an initial severity and triage assessment
- an estimated path to remediation
- notice when the issue is fixed
- release note credit unless anonymity is requested

## Security Best Practices

When using CONTEXA in production:

- keep CONTEXA updated
- use environment variables or a secure secret manager for credentials and API keys
- enable TLS for all network communication
- apply least privilege to IAM and policy configuration
- review and rotate credentials regularly
- protect administrative and benchmark publication surfaces separately from public application traffic