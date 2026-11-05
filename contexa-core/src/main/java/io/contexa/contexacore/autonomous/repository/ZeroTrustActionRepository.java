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

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.time.Duration;
import java.util.Map;

/**
 * Abstraction for Zero Trust action storage and retrieval.
 * Implementations: ZeroTrustActionRedisRepository (distributed), InMemoryZeroTrustActionRepository (standalone).
 */
public interface ZeroTrustActionRepository {


    ZeroTrustAction getCurrentAction(String userId);

    ZeroTrustAction getCurrentAction(String userId, String contextBindingHash);

    /**
     * docs/agent A5-1: the action in effect for a subject, read under its own key ({@link ZeroTrustSubject#storageKey}).
     * An agent acting for a person also reads the person's BLOCK: a blocked person's delegation stops with the account
     * (as the delegator's authority does, A1-8); the person's other decisions never answer the agent's request.
     */
    default ZeroTrustAction currentActionOf(ZeroTrustSubject subject, String contextBindingHash) {
        return subject.currentAction(this, contextBindingHash);
    }

    /** docs/agent A5-1: {@link #currentActionOf(ZeroTrustSubject, String)} without a context binding. */
    default ZeroTrustAction currentActionOf(ZeroTrustSubject subject) {
        return subject.currentAction(this);
    }

    ZeroTrustAnalysisData getAnalysisData(String userId);

    ZeroTrustAction getActionFromHash(String userId);

    ZeroTrustAction getPreviousActionFromHash(String userId);

    ZeroTrustAction getLastVerifiedAction(String userId);

    long getBlockMfaFailCount(String userId);

    boolean isStale(String userId, long maxAgeMs);


    boolean isBlockMfaPending(String userId);

    void setBlockMfaPending(String userId);

    boolean hasEscalateRetry(String userId);

    void setEscalateRetry(String userId, Duration ttl);


    void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields);

    /**
     * Stores the final decision of an analysis. The built-in repositories keep an active
     * user-level CHALLENGE or ESCALATE when the decision is less strict, whichever session it was
     * analysed for, and return {@code true} because the stricter action stays in effect.
     *
     * @return {@code false} only when the decision could not be written; a later decision of the same user that has
     *         replaced it since is no failed write
     */
    default boolean saveFinalAction(
            String userId,
            ZeroTrustAction action,
            Map<String, Object> additionalFields) {
        saveAction(userId, action, additionalFields);
        return true;
    }

    /** How the write of a final decision ended (W5-3). */
    enum FinalActionWrite {
        /** The decision is the action in effect. */
        APPLIED,
        /** A stricter user-level action stays in effect, so the less strict decision was not written. */
        KEPT_STRICTER,
        /** The decision could not be written. */
        FAILED
    }

    /**
     * Stores the final decision of an analysis as {@link #saveFinalAction} does and tells whether it took effect: a
     * less strict decision kept out by a stricter action in effect is KEPT_STRICTER, so that it is not learned as an
     * allowed request (W5-3).
     */
    default FinalActionWrite writeFinalAction(
            String userId,
            ZeroTrustAction action,
            Map<String, Object> additionalFields) {
        return saveFinalAction(userId, action, additionalFields) ? FinalActionWrite.APPLIED : FinalActionWrite.FAILED;
    }

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction);

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash);


    void setBlockedFlag(String userId);

    void removeBlockedFlag(String userId);

    void clearBlockMfaPending(String userId);

    long incrementBlockMfaFailCount(String userId);

    void removeAllUserData(String userId);

    /**
     * docs/agent A5-1: removes the decisions of every agent that acted for the user (their keys
     * {@code <user>::agent::<id>}), as the user's account is deleted. A repository that keeps no agent keys has nothing
     * to remove.
     */
    default void removeAllAgentData(String userId) {
    }

    /**
     * Clears logout state only when no actor BLOCK, ESCALATE or CHALLENGE is present.
     * Custom repositories retain actor state until they implement this contract.
     * Explicit resets continue to use removeAllUserData.
     */
    default void removeLogoutData(String userId) {
    }

    /**
     * Records that a final decision for the actor context was produced but could not be
     * written to the decision observation store, so no runtime action was applied.
     * While the marker is present, new analysis for the same actor context is not requested.
     * Custom repositories that do not implement this contract keep requesting analysis.
     */
    default void markDecisionAuditPending(String userId, String contextBindingHash, Duration ttl) {
    }

    default boolean isDecisionAuditPending(String userId, String contextBindingHash) {
        return false;
    }

    default void clearDecisionAuditPending(String userId, String contextBindingHash) {
    }


    void approveOverrideAtomically(String userId, ZeroTrustAction newAction);

    /**
     * What a stored ESCALATE ends as when it is read: with allow-escalate-final-action off an ESCALATE is internal to the
     * analysis, so one left in the store (by an earlier version or an earlier setting) becomes this action, stored with
     * this action's own TTL, and no reader meets it again. Null, the default, keeps it: it restricts until an approved
     * override or, past its TTL, the access filter's promotion. A BLOCK is not stored here, as a block also keeps its
     * flag and its record: the stored ESCALATE stays for the access filter, which writes them.
     * A repository that does not implement this keeps what it stores; the access filter then ends the ESCALATE itself.
     *
     * @param action what the ESCALATE ends as, or null to keep it
     */
    default void setEscalateTerminalAction(ZeroTrustAction action) {
    }


    record ZeroTrustAnalysisData(
            String action,
            Double riskScore,
            Double confidence,
            String threatEvidence,
            Integer analysisDepth,
            String updatedAt,
            String reasoning,
            String reasoningSummary,
            String requestId,
            String contextBindingHash,
            String llmProposedAction
    ) {
        public ZeroTrustAnalysisData(
                String action,
                Double riskScore,
                Double confidence,
                String threatEvidence,
                Integer analysisDepth,
                String updatedAt
        ) {
            this(
                    action,
                    riskScore,
                    confidence,
                    threatEvidence,
                    analysisDepth,
                    updatedAt,
                    null,
                    null,
                    null,
                    null,
                    null
            );
        }

        public static ZeroTrustAnalysisData pending() {
            return new ZeroTrustAnalysisData(
                    ZeroTrustAction.PENDING_ANALYSIS.name(),
                    null,  null, null, null, null, null, null, null, null, null
            );
        }
    }
}

