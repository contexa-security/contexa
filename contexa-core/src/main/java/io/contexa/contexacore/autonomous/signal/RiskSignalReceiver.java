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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Acts on revocation and risk signals another system sent (docs/agent A5-8; IETF AIMS: no cached decision after a
 * revocation; OpenID SSF, CAEP, RISC). For every event of a verified token, the subject's decision in force is
 * invalidated with its cache, so the subject's next request is decided again; a restriction in force (BLOCK,
 * ESCALATE, CHALLENGE) stays, since a signal never weakens a decision. An event that ends sessions (session revoked,
 * credential compromised, account disabled or purged) also signs the subject out. Every event is audited.
 */
@Slf4j
public class RiskSignalReceiver {

    /** What a token's events did. */
    public record Receipt(String jti, List<String> subjects, List<String> eventTypes) {
    }

    private final ZeroTrustActionRepository actions;
    private final ZeroTrustSecurityService zeroTrust;
    private final Function<Map<String, Object>, String> subjects;
    private final CentralAuditFacade audit;
    /** The identifiers of the tokens acted on lately: a token pushed again is acknowledged and not acted on twice. */
    private final Map<String, Boolean> seen = Collections.synchronizedMap(new LinkedHashMap<>(256, 0.75f,
            false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > SEEN_CAPACITY;
        }
    });
    static final int SEEN_CAPACITY = 10_000;

    /**
     * @param subjects the user a subject identifier names ({@link #userOf} reads the {@code iss_sub}, {@code opaque},
     *                 {@code email} and {@code complex} formats; the host gives its own lookup of addresses)
     */
    public RiskSignalReceiver(ZeroTrustActionRepository actions, @Nullable ZeroTrustSecurityService zeroTrust,
                              Function<Map<String, Object>, String> subjects, @Nullable CentralAuditFacade audit) {
        this.actions = Objects.requireNonNull(actions, "actions");
        this.zeroTrust = zeroTrust;
        this.subjects = Objects.requireNonNull(subjects, "subjects");
        this.audit = audit;
    }

    /** Invalidates the decisions of the subjects the token's events name. */
    public Receipt receive(SecurityEventToken token) {
        List<String> invalidated = new ArrayList<>();
        List<String> types = new ArrayList<>();
        if (seen.putIfAbsent(token.issuer() + "|" + token.jti(), Boolean.TRUE) != null) {
            return new Receipt(token.jti(), invalidated, types);
        }
        token.events().forEach((type, event) -> {
            Object eventSubject = event != null ? event.get("subject") : null;
            @SuppressWarnings("unchecked")
            Map<String, Object> subjectId = eventSubject instanceof Map<?, ?> named
                    ? (Map<String, Object>) named : token.subjectId();
            String user = subjectId != null ? subjects.apply(subjectId) : null;
            types.add(type);
            if (!StringUtils.hasText(user)) {
                record(token, type, null, "UNKNOWN_SUBJECT");
                return;
            }
            invalidate(user, type);
            invalidated.add(user);
            record(token, type, user, SecurityEventToken.endsSessions(type) ? "SIGNED_OUT" : "DECIDED_AGAIN");
        });
        return new Receipt(token.jti(), invalidated, types);
    }

    private void invalidate(String user, String type) {
        // A restriction in force stays; an ALLOW or a pending decision goes, so the next request is decided again.
        actions.removeLogoutData(ZeroTrustUserKey.person(user));
        if (zeroTrust != null) {
            zeroTrust.invalidateDecisionCache(user);
            if (SecurityEventToken.endsSessions(type)) {
                zeroTrust.invalidateAllUserSessions(user, "Risk signal: " + type);
            }
        }
    }

    /**
     * The user a subject identifier names: {@code iss_sub} its {@code sub}, {@code opaque} its {@code id}, {@code
     * email} through the given lookup, {@code complex} its {@code user} member; null for any other.
     */
    @Nullable
    public static String userOf(Map<String, Object> subjectId, Function<String, String> userByEmail) {
        if (subjectId == null) {
            return null;
        }
        Object format = subjectId.get("format");
        if ("iss_sub".equals(format)) {
            return text(subjectId.get("sub"));
        }
        if ("opaque".equals(format)) {
            return text(subjectId.get("id"));
        }
        if ("email".equals(format)) {
            String email = text(subjectId.get("email"));
            return email != null && userByEmail != null ? userByEmail.apply(email) : null;
        }
        if ("complex".equals(format) && subjectId.get("user") instanceof Map<?, ?> user) {
            @SuppressWarnings("unchecked")
            Map<String, Object> named = (Map<String, Object>) user;
            return userOf(named, userByEmail);
        }
        return null;
    }

    private void record(SecurityEventToken token, String type, @Nullable String user, String outcome) {
        if (audit == null) {
            return;
        }
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("issuer", token.issuer());
            details.put("jti", token.jti());
            details.put("eventType", type);
            audit.recordSync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.RISK_SIGNAL_RECEIVED)
                    .principalName(user != null ? user : "unknown")
                    .resourceIdentifier(type.length() > 512 ? type.substring(0, 512) : type)
                    .eventSource("CORE")
                    .action("RISK_SIGNAL_RECEIVED")
                    .decision(outcome)
                    .outcome(outcome)
                    .reason("Signal from " + token.issuer())
                    .details(details)
                    .build());
        } catch (RuntimeException e) {
            log.error("Risk signal audit failed: jti={}", token.jti(), e);
        }
    }

    @Nullable
    private static String text(@Nullable Object value) {
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }
}
