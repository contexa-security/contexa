# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in CONTEXA, report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email `contex73@gmail.com`
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

## Limits of Sealed Evidence

Sealed decisions are hashed, signed with the keys of `contexa.security.evidence.signing` and linked to the package
sealed before them. Someone who can write to the database but holds no key cannot change a package, or remove one from
inside the chain, without the re-inspection failing. The seal alone cannot tell, as long as nothing about it is kept
outside the database:

- the newest package removed: no package names it yet
- every package from one point up to the newest lowered to an unsigned schema together, or every package from the
  oldest up to one point lowered and dated back together: both read as signing that began later
- a package removed from the part of the chain the retention may already have reached: older than the shorter of
  `contexa.pqa.oss.sealed-evidence.retention.period` and `clean-period`
- a package whose signature names a key the installation does not hold reads as changed only from the time its active
  key signs, and only with configured keys. Before that time, and with an ephemeral key or a signer that does not say it
  keeps its keys, it reads as not verifiable, since a retired or an ephemeral key looks the same; the package sealed after
  it still fails when its hash was computed again

Decision records follow the same rule: once older sealed records are kept, a record without its hash or signature reads
as changed, and once older records are signed with the active key, so does one that names a key never held. They share
the limits above, and a record taken off the end of the chain does not show.

Configure a persistent signing key: with the ephemeral key a start generates, packages read as not verifiable after a
restart.

## Security Best Practices

When using CONTEXA in production:

- keep CONTEXA updated
- use environment variables or a secure secret manager for credentials and API keys
- enable TLS for all network communication
- apply least privilege to IAM and policy configuration
- review and rotate credentials regularly
- protect administrative and benchmark publication surfaces separately from public application traffic