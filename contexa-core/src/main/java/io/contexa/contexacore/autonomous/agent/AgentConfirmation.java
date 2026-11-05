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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.springframework.lang.Nullable;

import java.time.Instant;

/**
 * A request of an agent waiting for, or given, the confirmation of the person accountable for it (docs/agent A5-2):
 * the person the agent acts for, or the sponsor of an agent acting on its own. The confirmation is bound to the one
 * request it was asked for ({@code requestHash}, A5-9) and is used once.
 *
 * @param confirmationId  the confirmation's identifier, which the agent polls
 * @param tenantId        the tenant, or null
 * @param subjectKind     {@code DELEGATED_AGENT} or {@code AUTONOMOUS_AGENT}
 * @param userId          the user the request runs as: the person for a delegated agent, the agent's own principal
 * @param agentId         the agent
 * @param delegationId    the delegation the request named, or null
 * @param recipientId     the person who confirms
 * @param requestHash     the request it is bound to ({@link AgentRequestBinding})
 * @param method          the request's method
 * @param target          the request's path and query, as a person reads them: what opens something is masked
 * @param trigger         why a confirmation was asked: {@link #DECISION_CHALLENGE}, {@link #DELEGATION_ENDED} or
 *                        {@link #REQUESTED}
 * @param reason          what the person is shown as the reason, or null
 * @param correlationId   the request the confirmation was asked on, or null
 * @param status          where it stands
 * @param createdAt       when it was asked
 * @param expiresAt       until when it may be decided; once approved, until when the approval may be used
 * @param decidedAt       when it was decided, or null
 * @param decidedBy       who decided it, or null
 * @param decisionNote    what the person wrote with the decision, or null
 * @param authorizationId the verifiable authorization the approval is recorded as ({@link AgentConfirmationAuthorizer}),
 *                        or null
 * @param usedAt          when the approved request ran, or null
 */
public record AgentConfirmation(String confirmationId, @Nullable String tenantId, String subjectKind, String userId,
                                String agentId, @Nullable String delegationId, String recipientId,
                                String requestHash, String method, String target, String trigger,
                                @Nullable String reason, @Nullable String correlationId, Status status,
                                Instant createdAt, Instant expiresAt, @Nullable Instant decidedAt,
                                @Nullable String decidedBy, @Nullable String decisionNote,
                                @Nullable String authorizationId, @Nullable Instant usedAt) {

    /** The decision in force for the agent asks for a confirmation (CHALLENGE). */
    public static final String DECISION_CHALLENGE = "DECISION_CHALLENGE";
    /** The person's delegation to the agent has ended (expired or not started yet), docs/agent F-2. */
    public static final String DELEGATION_ENDED = "DELEGATION_ENDED";
    /** The agent asked for it itself, for a request a policy lets through only once confirmed. */
    public static final String REQUESTED = "REQUESTED";

    /** Where a confirmation stands. */
    public enum Status {
        /** Waiting for the person. */
        PENDING,
        /** Approved and not used yet. */
        APPROVED,
        /** Refused by the person. */
        REJECTED,
        /** Not decided, or not used, in time: a refusal. */
        EXPIRED,
        /** The person reported the request; the agent was stopped. */
        REPORTED,
        /** Approved and used by the request it is bound to. */
        USED;

        /** Whether the request it is bound to is refused for good. */
        public boolean refused() {
            return this == REJECTED || this == EXPIRED || this == REPORTED;
        }
    }

    /** The key the decisions of the subject are kept under: the agent's own for a delegated agent. */
    public String subjectKey() {
        return "DELEGATED_AGENT".equals(subjectKind) ? LearningSubject.agentKey(userId, agentId)
                : ZeroTrustUserKey.person(userId);
    }

    /** The confirmation decided. */
    public AgentConfirmation decided(Status decision, Instant at, String by, @Nullable String note,
                                     @Nullable String authorization, Instant until) {
        return new AgentConfirmation(confirmationId, tenantId, subjectKind, userId, agentId, delegationId,
                recipientId, requestHash, method, target, trigger, reason, correlationId, decision, createdAt, until,
                at, by, note, authorization, usedAt);
    }

    /** The confirmation with another status, the rest kept. */
    public AgentConfirmation withStatus(Status next, @Nullable Instant used) {
        return new AgentConfirmation(confirmationId, tenantId, subjectKind, userId, agentId, delegationId,
                recipientId, requestHash, method, target, trigger, reason, correlationId, next, createdAt, expiresAt,
                decidedAt, decidedBy, decisionNote, authorizationId, used);
    }
}
