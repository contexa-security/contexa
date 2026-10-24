/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.signal;

import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.Map;

/**
 * A verified Security Event Token (RFC 8417) a transmitter pushed (docs/agent A5-8; OpenID SSF 1.0, CAEP 1.0, RISC):
 * who sent it, which subject it names, and its events by event type URI.
 *
 * @param issuer    the transmitter
 * @param jti       the token's identifier
 * @param issuedAt  when it was issued, or null
 * @param subjectId the subject identifier ({@code sub_id}, RFC 9493) of the token, or null when each event names its
 *                  own
 * @param events    the events by type URI, each with its members (an event may carry its own {@code subject})
 */
public record SecurityEventToken(String issuer, String jti, @Nullable Instant issuedAt,
                                 @Nullable Map<String, Object> subjectId, Map<String, Map<String, Object>> events) {

    /** CAEP: the subject's session was revoked. */
    public static final String SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    /** CAEP: the subject's risk level changed. */
    public static final String RISK_LEVEL_CHANGE =
            "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
    /** CAEP: a credential of the subject changed. */
    public static final String CREDENTIAL_CHANGE =
            "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    /** CAEP: the claims of the subject's tokens changed. */
    public static final String TOKEN_CLAIMS_CHANGE =
            "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
    /** RISC: a credential of the subject is compromised. */
    public static final String CREDENTIAL_COMPROMISE =
            "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
    /** RISC: the subject's account was disabled. */
    public static final String ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    /** RISC: the subject's account was purged. */
    public static final String ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged";

    public SecurityEventToken {
        events = events == null ? Map.of() : Map.copyOf(events);
    }

    /** Whether the event ends the subject's sessions: they are signed out, not only decided again. */
    public static boolean endsSessions(String eventType) {
        return SESSION_REVOKED.equals(eventType) || CREDENTIAL_COMPROMISE.equals(eventType)
                || ACCOUNT_DISABLED.equals(eventType) || ACCOUNT_PURGED.equals(eventType);
    }
}
