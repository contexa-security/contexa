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
package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * docs/agent F-5 (RW-1): what the confirmation an agent's request used says (A5-2): who approved it and when, when and
 * why it was asked, the authorization it was recorded as and when the request used it. The gate that lets the
 * confirmed request on keeps them on the request; the event publisher carries them into the request's decision context,
 * so the analysis of the request reads the person's confirmation as a fact. The times are the engine's own clock.
 */
public final class AgentConfirmationFacts {

    public static final String ID = "agentConfirmationId";
    public static final String DECIDED_BY = "agentConfirmationDecidedBy";
    public static final String DECIDED_AT = "agentConfirmationDecidedAt";
    public static final String ASKED_AT = "agentConfirmationAskedAt";
    public static final String TRIGGER = "agentConfirmationTrigger";
    public static final String AUTHORIZATION_ID = "agentConfirmationAuthorizationId";
    public static final String USED_AT = "agentConfirmationUsedAt";

    private AgentConfirmationFacts() {
    }

    /** The facts of a confirmation, the times as ISO-8601 instants; values not known are left out. */
    public static Map<String, Object> of(String confirmationId, @Nullable String decidedBy, @Nullable Instant decidedAt,
                                         @Nullable Instant askedAt, @Nullable String trigger,
                                         @Nullable String authorizationId, @Nullable Instant usedAt) {
        Map<String, Object> facts = new LinkedHashMap<>();
        put(facts, ID, confirmationId);
        put(facts, DECIDED_BY, decidedBy);
        put(facts, DECIDED_AT, decidedAt);
        put(facts, ASKED_AT, askedAt);
        put(facts, TRIGGER, trigger);
        put(facts, AUTHORIZATION_ID, authorizationId);
        put(facts, USED_AT, usedAt);
        return facts;
    }

    /** Keeps the facts on the request the confirmation is bound to. */
    public static void keep(HttpServletRequest request, Map<String, Object> facts) {
        if (request != null && facts != null && !facts.isEmpty()) {
            request.setAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION_FACTS, Map.copyOf(facts));
        }
    }

    /** The facts kept on the request this thread serves; empty when it used no confirmation. */
    public static Map<String, Object> current() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (!(attributes instanceof ServletRequestAttributes servlet)) {
            return Map.of();
        }
        Object facts = servlet.getRequest().getAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION_FACTS);
        if (!(facts instanceof Map<?, ?> map)) {
            return Map.of();
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        map.forEach((key, value) -> {
            if (key instanceof String name && value != null) {
                copy.put(name, value);
            }
        });
        return copy;
    }

    private static void put(Map<String, Object> facts, String key, @Nullable Object value) {
        if (value instanceof String text && text.isBlank()) {
            return;
        }
        if (value != null) {
            facts.put(key, value instanceof Instant instant ? instant.toString() : value);
        }
    }
}
