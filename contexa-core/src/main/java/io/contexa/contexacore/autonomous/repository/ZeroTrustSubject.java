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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Whose decision a request reads and writes (docs/agent A5-1): the tenant, the user, the kind of subject, the agent and
 * the delegation. A person, a service client and an agent acting on its own each act under an identity of their own,
 * so their decisions stay under the user ID as before. An agent acting for a person shares that person's user ID, so
 * its decisions are kept under a key of its own ({@code <user>::agent::<agent id>}, the shape of the agent's learning
 * key, A3-1): an agent's CHALLENGE or BLOCK never stops the person's own work, and the person's never answers the
 * agent's request. The delegation and the tenant are carried but not keyed: a token may name no delegation before its
 * record is looked up, and a person's key names no tenant either.
 *
 * @param tenantId     the request's tenant, or null
 * @param userId       the request's user: the person a delegated agent acts for, or the subject's own identity
 * @param kind         the subject kind (A1-3)
 * @param agentId      the agent of an agent's request, or null
 * @param delegationId the delegation an agent's request names, or null
 */
public record ZeroTrustSubject(@Nullable String tenantId, String userId, SubjectKind kind, @Nullable String agentId,
                               @Nullable String delegationId) {

    private static final String EVENT_SUBJECT_KIND = "executionSubjectKind";

    public ZeroTrustSubject {
        if (!StringUtils.hasText(userId)) {
            throw new IllegalArgumentException("A decision subject needs a user");
        }
        userId = userId.trim();
        kind = kind != null ? kind : SubjectKind.HUMAN_USER;
        agentId = StringUtils.hasText(agentId) ? agentId.trim() : null;
    }

    /** A person's subject, keyed by the user ID alone. */
    public static ZeroTrustSubject person(String userId) {
        return new ZeroTrustSubject(null, userId, SubjectKind.HUMAN_USER, null, null);
    }

    /**
     * The subject of a request the bridge stamped: a delegation that names an agent is the agent acting for the user,
     * an agent without a delegation acts on its own; no stamp is the user's own request. Null without a user.
     */
    @Nullable
    public static ZeroTrustSubject of(@Nullable String userId, @Nullable DelegationStamp stamp) {
        return of(userId, stamp, null);
    }

    /**
     * The subject of a request the bridge stamped, with the request's tenant: an agent's subject carries it, as the
     * event's subject does ({@link #of(SecurityEvent)}), so the agent's delegation and registration are read in the
     * tenant they were recorded in. A person's subject stays as {@link #person(String)} makes it.
     */
    @Nullable
    public static ZeroTrustSubject of(@Nullable String userId, @Nullable DelegationStamp stamp,
                                      @Nullable String tenantId) {
        if (!StringUtils.hasText(userId)) {
            return null;
        }
        if (stamp == null || !StringUtils.hasText(stamp.agentId())) {
            return person(userId);
        }
        Object delegationId = stamp.attributes().get("delegationId");
        return new ZeroTrustSubject(StringUtils.hasText(tenantId) ? tenantId.trim() : null, userId,
                stamp.delegated() ? SubjectKind.DELEGATED_AGENT : SubjectKind.AUTONOMOUS_AGENT, stamp.agentId(),
                delegationId != null ? delegationId.toString() : null);
    }

    /** The subject of an event, as the publisher recorded it (A1-3); null without a user. */
    @Nullable
    public static ZeroTrustSubject of(@Nullable SecurityEvent event) {
        LearningSubject learning = LearningSubject.of(event);
        if (learning == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        return new ZeroTrustSubject(learning.tenantId(), learning.userId(), kindOf(metadata.get(EVENT_SUBJECT_KIND)),
                learning.agentId(), learning.delegationId());
    }

    /**
     * The subject of an authorization event's payload or an event's metadata, as the publisher recorded it
     * ({@code executionSubjectKind}, {@code agentId}, {@code delegationId}); null without a user.
     */
    @Nullable
    public static ZeroTrustSubject ofFacts(@Nullable String userId, @Nullable Map<String, ?> facts) {
        if (!StringUtils.hasText(userId)) {
            return null;
        }
        Map<String, ?> given = facts != null ? facts : Map.of();
        SubjectKind kind = kindOf(given.get(EVENT_SUBJECT_KIND));
        boolean agent = kind == SubjectKind.DELEGATED_AGENT || kind == SubjectKind.AUTONOMOUS_AGENT;
        Object agentId = agent ? given.get("agentId") : null;
        Object delegationId = agent ? given.get("delegationId") : null;
        Object tenantId = given.get("tenantId");
        return new ZeroTrustSubject(tenantId != null ? tenantId.toString() : null, userId, kind,
                agentId != null ? agentId.toString() : null, delegationId != null ? delegationId.toString() : null);
    }

    /**
     * The action in effect for the subject, read under its own key with the context binding. An agent acting for a
     * person also reads the person's BLOCK: a blocked person's delegation stops with the account (as the delegator's
     * authority does, A1-8); the person's other decisions never answer the agent's request. Only the user-keyed
     * methods of the repository are called, so a person's read is the call it was before.
     */
    public ZeroTrustAction currentAction(ZeroTrustActionRepository repository, @Nullable String contextBindingHash) {
        return withDelegatorBlock(repository, repository.getCurrentAction(storageKey(), contextBindingHash));
    }

    /** {@link #currentAction(ZeroTrustActionRepository, String)} through the one-argument read (no binding). */
    public ZeroTrustAction currentAction(ZeroTrustActionRepository repository) {
        return withDelegatorBlock(repository, repository.getCurrentAction(storageKey()));
    }

    private ZeroTrustAction withDelegatorBlock(ZeroTrustActionRepository repository, ZeroTrustAction action) {
        if (delegatedAgent() && action != ZeroTrustAction.BLOCK
                && repository.getCurrentAction(userId) == ZeroTrustAction.BLOCK) {
            return ZeroTrustAction.BLOCK;
        }
        return action;
    }

    /** Whether an agent acts for the person whose user ID the request carries. */
    public boolean delegatedAgent() {
        return kind == SubjectKind.DELEGATED_AGENT && agentId != null;
    }

    /** The key the subject's decisions are stored under: the user ID, or the delegated agent's own key. */
    public String storageKey() {
        return delegatedAgent() ? LearningSubject.agentKey(userId, agentId) : userId;
    }

    private static SubjectKind kindOf(@Nullable Object value) {
        if (value == null) {
            return SubjectKind.HUMAN_USER;
        }
        try {
            return SubjectKind.valueOf(value.toString().trim());
        } catch (IllegalArgumentException e) {
            return SubjectKind.HUMAN_USER;
        }
    }
}
