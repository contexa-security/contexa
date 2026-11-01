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
package io.contexa.contexacore.autonomous.baseline;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import org.springframework.lang.Nullable;

import java.util.Map;

/**
 * Whose learning a request belongs to (docs/agent A3-1). A person's request learns and reads that person's baseline,
 * work profile and past records under the person's own key. An agent's request, for a person or on its own, learns and
 * reads under a key of its own ({@code <user>::agent::<agent id>}), so that an agent's activity never becomes a person's
 * usual behaviour and a person's history is never read as an agent's.
 *
 * @param tenantId     the request's tenant, or null
 * @param userId       the request's user: the person a delegated agent acts for, or the agent's client or account
 * @param agentId      the agent of an agent's request, or null for a person's
 * @param delegationId the delegation an agent's request runs under, when it names one
 * @param subjectKind  the publisher's subject kind (HUMAN_USER, DELEGATED_AGENT, AUTONOMOUS_AGENT, SERVICE_CLIENT), or
 *                     null when the event does not say
 */
public record LearningSubject(@Nullable String tenantId, String userId, @Nullable String agentId,
                              @Nullable String delegationId, @Nullable String subjectKind) {

    /** What joins a user and an agent in an agent's learning key. */
    public static final String AGENT_KEY = "::agent::";
    /** The decision document metadata the subject is written under (A3-1). */
    public static final String SUBJECT_KIND = "subjectKind";
    public static final String AGENT_ID = "agentId";
    public static final String DELEGATION_ID = "delegationId";

    private static final String EVENT_SUBJECT_KIND = "executionSubjectKind";

    /** The subject of the event's own user, or null without one. */
    @Nullable
    public static LearningSubject of(@Nullable SecurityEvent event) {
        return of(event, event != null ? event.getUserId() : null);
    }

    /** The subject of the given user within the event, or null without a user. */
    @Nullable
    public static LearningSubject of(@Nullable SecurityEvent event, @Nullable String userId) {
        String user = text(userId);
        if (user == null) {
            return null;
        }
        Map<String, Object> metadata = event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
        String kind = text(metadata.get(EVENT_SUBJECT_KIND));
        boolean agent = SubjectKind.DELEGATED_AGENT.name().equals(kind) || SubjectKind.AUTONOMOUS_AGENT.name().equals(kind);
        String agentId = agent ? text(metadata.get(AGENT_ID)) : null;
        String delegationId = agentId != null ? delegationId(metadata) : null;
        return new LearningSubject(tenantOf(event), user, agentId, delegationId, kind);
    }

    /**
     * The tenant every learning of the request is kept under, its baseline, work profile and held requests alike
     * (QF-22): {@code tenantId}, then {@code tenant_id}, as the canonical actor and the sealed evidence read it; null
     * without one. An organization the host names is the organization of the organization baseline, not a tenant.
     */
    @Nullable
    public static String tenantOf(@Nullable SecurityEvent event) {
        Map<String, Object> metadata = event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
        return firstText(metadata.get("tenantId"), metadata.get("tenant_id"));
    }

    /**
     * The key the subject's learning is kept under within its tenant ({@code tenant::key}), the key alone without a
     * tenant, as the personal baseline's key is written (W5-10 D9, QF-29).
     */
    public String tenantKey() {
        return BaselineDataStore.userKey(tenantId, key());
    }

    /** The learning key of an agent for a user, as {@link #key()} writes it for the agent's requests. */
    public static String agentKey(String userId, String agentId) {
        return userId + AGENT_KEY + agentId;
    }

    /** Whether an agent sends the request. */
    public boolean agent() {
        return agentId != null;
    }

    /** The key the subject's learning is stored under: the user for a person, the user and the agent for an agent. */
    public String key() {
        return agentId != null ? agentKey(userId, agentId) : userId;
    }

    @Nullable
    private static String delegationId(Map<String, Object> metadata) {
        String stated = text(metadata.get(DELEGATION_ID));
        if (stated != null) {
            return stated;
        }
        if (metadata.get(LearningPromotionPolicy.DECIDED_CONTEXT) instanceof CanonicalSecurityContext decided
                && decided.getAttributes() != null) {
            return text(decided.getAttributes().get(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE));
        }
        return null;
    }

    @Nullable
    private static String firstText(Object... values) {
        for (Object value : values) {
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
