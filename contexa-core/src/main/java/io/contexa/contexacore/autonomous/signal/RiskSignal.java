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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A change of a subject's risk level that a Contexa decision made (docs/agent A5-8, CAEP risk-level-change): the
 * subject, the level before and after, and the decision's reason.
 *
 * @param tenantId      the tenant, or null
 * @param userId        the user the decision was about
 * @param agentId       the agent, for an agent's request, else null
 * @param previousLevel the level before ({@code LOW}, {@code MEDIUM}, {@code HIGH})
 * @param currentLevel  the level now
 * @param action        the decision
 * @param reason        the decision's reason, or null
 * @param decidedAt     when it was decided
 */
public record RiskSignal(@Nullable String tenantId, String userId, @Nullable String agentId, String previousLevel,
                         String currentLevel, ZeroTrustAction action, @Nullable String reason, Instant decidedAt) {

    public static final String LOW = "LOW";
    public static final String MEDIUM = "MEDIUM";
    public static final String HIGH = "HIGH";

    /** The risk level a decision stands for: ALLOW low, CHALLENGE medium, ESCALATE and BLOCK high, none unknown. */
    @Nullable
    public static String levelOf(@Nullable ZeroTrustAction action) {
        if (action == null) {
            return null;
        }
        return switch (action) {
            case ALLOW -> LOW;
            case CHALLENGE -> MEDIUM;
            case ESCALATE, BLOCK -> HIGH;
            default -> null;
        };
    }

    /**
     * The claims of a CAEP risk-level-change Security Event Token for this signal (unsigned): an emitter signs them
     * with its key and pushes them to its receivers.
     *
     * @param issuer   the emitter's issuer
     * @param audience the receiver
     * @param jti      the token's identifier
     */
    public Map<String, Object> caepClaims(String issuer, String audience, String jti) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("format", "iss_sub");
        subject.put("iss", issuer);
        subject.put("sub", agentId != null ? userId + "::agent::" + agentId : userId);
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("principal", agentId != null ? "AGENT" : "USER");
        event.put("current_level", currentLevel);
        event.put("previous_level", previousLevel);
        if (reason != null) {
            event.put("risk_reason", reason);
        }
        event.put("event_timestamp", decidedAt.getEpochSecond());
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("aud", List.of(audience));
        claims.put("jti", jti);
        claims.put("iat", decidedAt.getEpochSecond());
        claims.put("sub_id", subject);
        claims.put("events", Map.of(SecurityEventToken.RISK_LEVEL_CHANGE, event));
        return claims;
    }
}
