# Contexa MFA Custom UI Guide

Complete guide for customizing Multi-Factor Authentication (MFA) user interfaces in Contexa Identity Platform.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

---

## Overview

Contexa Identity Platform provides two ways to implement MFA user interfaces:

### 1. **Default UI** (Zero Configuration)
Automatically generated HTML pages with contexa-mfa-sdk.js integration.

### 2. **Custom UI** (Fully Customizable)
Bring your own React, Vue, Angular, or any frontend framework.

### Key Benefits

- ✅ **65% Code Reduction**: 1,854 lines → 650 lines
- ✅ **Zero Code Duplication**: 360 duplicate lines eliminated
- ✅ **Framework Agnostic**: Works with any frontend framework
- ✅ **100% Server Compatible**: No server logic changes required
- ✅ **Type-Safe SDK**: Unified JavaScript API

---

## Quick Start

### Option 1: Use Default Pages (Recommended for Most Projects)

No configuration needed! Default pages are automatically generated.

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
        .with(new SecurityPlatformConfiguration(), platform -> platform
            .mfa(mfa -> mfa
                .ott(ott -> ott
                    .tokenLength(6)
                    .expirationSeconds(300)
                )
                .passkey(passkey -> passkey
                    .rpId("your-domain.com")
                    .rpName("Your Application")
                )
            )
        )
        .build();
}
```

**That's it!** MFA pages are automatically available at:
- `/mfa/select-factor` - Factor selection
- `/mfa/ott/request-code-ui` - OTT code request
- `/mfa/challenge/ott` - OTT code verification
- `/mfa/challenge/passkey` - Passkey authentication

### Option 2: Use Custom Pages

Configure custom URLs and implement your own controllers.

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
        .with(new SecurityPlatformConfiguration(), platform -> platform
            .mfa(mfa -> mfa
                .ott(ott -> ott.tokenLength(6).expirationSeconds(300))
                .passkey(passkey -> passkey.rpId("your-domain.com"))
                .mfaPage(page -> page
                    .selectFactorPage("/custom/mfa/select")
                    .ottPages("/custom/mfa/ott-request", "/custom/mfa/ott-verify")
                    .passkeyChallengePages("/custom/mfa/passkey")
                )
            )
        )
        .build();
}
```

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (Your Choice)                    │
│  React / Vue / Angular / Vanilla JS + contexa-mfa-sdk.js   │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│           DefaultMfaPageGeneratingFilter                    │
│  • Generates default HTML if no custom page configured      │
│  • Forwards to custom controller if configured              │
│  • Injects FactorContext as request attributes              │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  MfaApiController                           │
│  • GET  /api/mfa/context   (Load MFA context)              │
│  • GET  /api/mfa/config    (Load endpoint URLs)            │
│  • POST /api/mfa/select-factor (Select authentication)     │
│  • POST /api/mfa/request-ott-code (Request OTT code)       │
│  • POST /api/mfa/assertion/options (Get Passkey options)   │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│            Spring State Machine (17 States)                 │
│  • Manages MFA workflow and state transitions              │
│  • Persists state in Redis                                  │
│  • Validates all state transitions                          │
└─────────────────────────────────────────────────────────────┘
```

### SDK Architecture

```javascript
// contexa-mfa-sdk.js Structure

ContexaMFA
├── Client (Main API)
│   ├── init()
│   ├── selectFactor(type)
│   ├── verifyOtt(code)
│   ├── verifyPasskey()
│   ├── getStatus()
│   └── cancel()
│
├── Utils (Helpers)
│   ├── getCsrfToken()
│   ├── getDeviceId()
│   ├── base64UrlToArrayBuffer()
│   └── arrayBufferToBase64Url()
│
├── StateTracker (State Management)
│   ├── updateFromServerResponse()
│   ├── canTransitionTo(state)
│   └── isTerminalState()
│
└── version: '1.0.0'
```

---

## API Reference

### Server REST API

#### `GET /api/mfa/context`

Load current MFA session context.

**Response:**
```json
{
  "mfaSessionId": "abc123",
  "username": "user@example.com",
  "currentState": "AWAITING_FACTOR_SELECTION",
  "registeredFactors": ["OTT", "PASSKEY"],
  "completedFactors": [],
  "flowType": "mfa"
}
```

#### `GET /api/mfa/config`

Load all MFA endpoint URLs.

**Response:**
```json
{
  "mfa": {
    "selectFactor": "/mfa/select-factor",
    "configure": "/mfa/configure",
    "failure": "/mfa/failure"
  },
  "ott": {
    "challenge": "/mfa/challenge/ott",
    "loginProcessing": "/login/mfa-ott"
  },
  "passkey": {
    "challenge": "/mfa/challenge/passkey",
    "loginProcessing": "/login/mfa-webauthn"
  },
  "api": {
    "selectFactor": "/api/mfa/select-factor",
    "context": "/api/mfa/context",
    "status": "/api/mfa/status"
  }
}
```

#### `POST /api/mfa/select-factor`

Select authentication factor.

**Request:**
```json
{
  "factor": "OTT"
}
```

**Response:**
```json
{
  "status": "FACTOR_SELECTED",
  "selectedFactor": "OTT",
  "nextStepUrl": "/mfa/ott/request-code-ui",
  "currentState": "AWAITING_FACTOR_CHALLENGE_INITIATION"
}
```

#### `POST /api/mfa/request-ott-code`

Request OTT code resend.

**Response:**
```json
{
  "status": "OTT_CODE_REQUESTED",
  "message": "OTT code has been resent"
}
```

#### `POST /api/mfa/assertion/options`

Get Passkey assertion options for WebAuthn.

**Response:**
```json
{
  "status": "OPTIONS_GENERATED",
  "assertionOptions": {
    "challenge": "base64url-encoded-challenge",
    "rpId": "your-domain.com",
    "timeout": 60000,
    "userVerification": "preferred"
  }
}
```

### JavaScript SDK API

#### `ContexaMFA.Client`

Main SDK client for MFA operations.

```javascript
const mfa = new ContexaMFA.Client({
    autoInit: true,      // Auto-initialize on creation
    autoRedirect: true   // Auto-redirect on success
});
```

##### `async init()`

Initialize SDK and load MFA context.

```javascript
const context = await mfa.init();
console.log(context.registeredFactors); // ['OTT', 'PASSKEY']
```

##### `async selectFactor(factorType)`

Select authentication factor.

```javascript
const result = await mfa.selectFactor('OTT');
// Auto-redirects to next page if autoRedirect: true
```

##### `async verifyOtt(code)`

Verify OTT code.

```javascript
const result = await mfa.verifyOtt('123456');
if (result.status === 'SUCCESS') {
    // Auto-redirects to success page
}
```

##### `async verifyPasskey()`

Perform Passkey authentication.

```javascript
try {
    const result = await mfa.verifyPasskey();
    // Handles WebAuthn API automatically
    // Auto-redirects on success
} catch (error) {
    console.error('Passkey authentication failed:', error);
}
```

##### `async getStatus()`

Get current MFA status.

```javascript
const status = await mfa.getStatus();
console.log(status.currentState); // Current state machine state
```

##### `async cancel()`

Cancel MFA process.

```javascript
await mfa.cancel();
// Auto-redirects to login page
```

---

## Examples

### React Example

```jsx
// CustomMfaSelect.jsx
import React, { useState, useEffect } from 'react';

function CustomMfaSelect() {
    const [context, setContext] = useState(null);
    const [loading, setLoading] = useState(true);
    const mfa = new ContexaMFA.Client({ autoRedirect: true });

    useEffect(() => {
        mfa.init().then(ctx => {
            setContext(ctx);
            setLoading(false);
        });
    }, []);

    const handleSelectFactor = async (factor) => {
        try {
            await mfa.selectFactor(factor);
        } catch (error) {
            alert('Failed: ' + error.message);
        }
    };

    if (loading) return <div>Loading...</div>;

    return (
        <div className="mfa-container">
            <h1>Choose Authentication Method</h1>
            {context.registeredFactors.map(factor => (
                <button
                    key={factor}
                    onClick={() => handleSelectFactor(factor)}
                    className="factor-button"
                >
                    {factor === 'OTT' ? 'Email Code' : 'Passkey'}
                </button>
            ))}
        </div>
    );
}

export default CustomMfaSelect;
```

### Vue Example

```vue
<!-- CustomMfaOttVerify.vue -->
<template>
  <div class="mfa-verify">
    <h1>Enter Verification Code</h1>
    <input
      v-model="code"
      type="text"
      placeholder="6-digit code"
      maxlength="6"
    />
    <button @click="verifyCode" :disabled="loading">
      {{ loading ? 'Verifying...' : 'Verify' }}
    </button>
    <button @click="resendCode">Resend Code</button>
  </div>
</template>

<script>
export default {
  data() {
    return {
      code: '',
      loading: false,
      mfa: new ContexaMFA.Client({ autoRedirect: true })
    };
  },
  methods: {
    async verifyCode() {
      this.loading = true;
      try {
        await this.mfa.verifyOtt(this.code);
      } catch (error) {
        alert('Verification failed: ' + error.message);
      } finally {
        this.loading = false;
      }
    },
    async resendCode() {
      try {
        await this.mfa.apiClient.requestOttCode();
        alert('Code resent successfully');
      } catch (error) {
        alert('Resend failed: ' + error.message);
      }
    }
  }
};
</script>
```

### Angular Example

```typescript
// custom-mfa-passkey.component.ts
import { Component, OnInit } from '@angular/core';

declare const ContexaMFA: any;

@Component({
  selector: 'app-custom-mfa-passkey',
  template: `
    <div class="mfa-passkey">
      <h1>🔐 Passkey Authentication</h1>
      <p>Use your biometric or security key</p>
      <button (click)="authenticate()" [disabled]="loading">
        {{ loading ? 'Authenticating...' : 'Start Authentication' }}
      </button>
    </div>
  `
})
export class CustomMfaPasskeyComponent implements OnInit {
  loading = false;
  mfa: any;

  ngOnInit() {
    this.mfa = new ContexaMFA.Client({ autoRedirect: true });
    this.mfa.init();
  }

  async authenticate() {
    this.loading = true;
    try {
      await this.mfa.verifyPasskey();
    } catch (error) {
      alert('Authentication failed: ' + error.message);
    } finally {
      this.loading = false;
    }
  }
}
```

### Vanilla JavaScript Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>Custom MFA</title>
    <script src="/js/contexa-mfa-sdk.js"></script>
</head>
<body>
    <div id="mfa-container"></div>

    <script>
        (async function() {
            const mfa = new ContexaMFA.Client({ autoRedirect: true });
            const context = await mfa.init();

            const container = document.getElementById('mfa-container');
            container.innerHTML = '<h1>Choose Factor</h1>';

            context.registeredFactors.forEach(factor => {
                const button = document.createElement('button');
                button.textContent = factor;
                button.onclick = async () => {
                    button.disabled = true;
                    try {
                        await mfa.selectFactor(factor);
                    } catch (error) {
                        alert('Error: ' + error.message);
                        button.disabled = false;
                    }
                };
                container.appendChild(button);
            });
        })();
    </script>
</body>
</html>
```

---

## Troubleshooting

### Common Issues

#### Issue: "No active MFA session found"

**Cause:** MFA session expired or not initiated.

**Solution:**
- Check that primary authentication (1st factor) completed successfully
- Verify Redis is running and accessible
- Check session timeout settings

#### Issue: "Failed to load MFA configuration"

**Cause:** `/api/mfa/config` endpoint not accessible.

**Solution:**
```java
// Ensure MfaApiController is properly registered
@RestController
@RequestMapping("/api/mfa")
public class MfaApiController {
    // Endpoints should be available
}
```

#### Issue: "Passkey authentication not working"

**Cause:** HTTPS required for WebAuthn.

**Solution:**
- Use HTTPS in production
- For local development, use `localhost` (HTTP allowed)
- Configure correct `rpId` in DSL

```java
.passkey(passkey -> passkey
    .rpId("localhost") // For development
    // .rpId("your-domain.com") // For production
)
```

#### Issue: "Custom pages not loading"

**Cause:** Filter not registered or URL mismatch.

**Solution:**
1. Check DSL configuration:
```java
.mfaPage(page -> page.selectFactorPage("/custom/mfa/select"))
```

2. Verify controller mapping:
```java
@GetMapping("/select") // Should match DSL URL minus "/custom/mfa"
public String selectFactorPage() { ... }
```

3. Check filter order in SecurityPlatformConfiguration

### Debug Mode

Enable debug logging:

```properties
# application.yml
logging:
  level:
    io.contexa.contexaidentity.security: DEBUG
    io.contexa.contexaidentity.controller: DEBUG
```

### Migration from Legacy Files

If migrating from legacy HTML/JS files:

1. **Replace script tags:**
```html
<!-- Old -->
<script src="/js/mfa-select-factor.js"></script>
<script src="/js/mfa-state-tracker.js"></script>

<!-- New -->
<script src="/js/contexa-mfa-sdk.js"></script>
```

2. **Update JavaScript code:**
```javascript
// Old
const mfaSessionId = sessionStorage.getItem('mfaSessionId');
// ... manual CSRF, device ID, state tracking ...

// New
const mfa = new ContexaMFA.Client();
await mfa.init(); // Handles everything automatically
```

3. **Remove duplicated code:**
- CSRF handling (8 duplicates → 0)
- Device ID generation (6 duplicates → 0)
- WebAuthn conversions (3 duplicates → 0)
- State validation (7 duplicates → 0)

---

## Additional Resources

- **Source Code:** `contexa-identity/src/main/resources/static/js/contexa-mfa-sdk.js`
- **Example Controller:** `CustomMfaController.java`
- **Filter Implementation:** `DefaultMfaPageGeneratingFilter.java`
- **DSL Reference:** `MfaPageConfigurer.java`

## Support

For issues or questions:
1. Check this documentation first
2. Review example code in `controller/example/`
3. Enable debug logging
4. Contact support with logs and configuration

---

**Version:** 1.0.0
**Last Updated:** 2024
**License:** Apache 2.0
