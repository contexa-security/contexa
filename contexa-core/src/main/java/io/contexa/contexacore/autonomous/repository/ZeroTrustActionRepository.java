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

import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Abstraction for Zero Trust action storage and retrieval.
 * Implementations: ZeroTrustActionRedisRepository (distributed), InMemoryZeroTrustActionRepository (standalone).
 * <p>
 * Every {@code userId} here is a key, never a bare name: {@link ZeroTrustSubject#storageKey()} for a request's subject,
 * {@code ZeroTrustUserKey.person} for a name. A name handed over as it is would read a console session's or an agent's
 * decisions if it were spelled as their key.
 */
public interface ZeroTrustActionRepository {

    /**
     * Q-5: the field of a final decision that marks a CHALLENGE no model decided: the analysis failed, so nothing is
     * known of the user. It lasts {@link #TECHNICAL_CHALLENGE_TTL} instead of a CHALLENGE's own TTL and gives way to
     * what the model decides next. A CHALLENGE the model decided is never replaced by one that carries this field.
     */
    String TECHNICAL_CHALLENGE = "technicalChallenge";

    /** Q-5: how long a CHALLENGE no model decided stays in force. */
    Duration TECHNICAL_CHALLENGE_TTL = Duration.ofSeconds(60);

    /** Whether a final decision the model reached: only such a decision lifts a CHALLENGE no model decided. */
    String LLM_DECISION_PRESENT = "llmDecisionPresent";


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

    /**
     * The context the user's decision was reached for: the one of the decision in its TTL, else the last verified one,
     * which outlasts it by up to 24 hours. A request from any other context changed session, address or browser. Null
     * when nothing is on record, which is no change: a repository that keeps no such record answers null.
     * <p>
     * Unlike the reads of an action, this read does not answer for a store it could not read: null would let a request
     * go on as one of the context on record, so a failure stays a failure for its caller.
     */
    @Nullable
    default String decidedContext(String userId) {
        return null;
    }

    /**
     * Q-5: whether the action in force is a CHALLENGE no model decided. A repository that keeps no such mark answers
     * false: its CHALLENGE stands as a decided one.
     */
    default boolean isTechnicalChallenge(String userId) {
        return false;
    }

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

    /**
     * Asks every session of the user to verify where no analysis decided: a person whose sign-ins passed the decisions
     * of a new context allowed in a short window. It is a CHALLENGE as a decided one is, for the CHALLENGE's own TTL,
     * ended by the step-up of a session (that session alone), an administrator's override or a stricter decision; a
     * model's less strict decision does not lift it. It never takes the place of a BLOCK (stored or flagged), an
     * ESCALATE or a CHALLENGE a model decided, nor of a CHALLENGE held for the sessions that did not answer one, which
     * already asks the given context: those stay as they are and KEPT_STRICTER is returned. A short CHALLENGE no model
     * decided gives way to it.
     * <p>
     * The built-in repositories check and write at once. This default reads the action in force first and writes over
     * nothing stricter, so a stricter decision written between the two would be replaced.
     *
     * @param fields the fields of the CHALLENGE: the context it was asked for ({@code contextBindingHash}) and why
     * @return APPLIED when it was written, KEPT_STRICTER when what is in force already asks as much, FAILED without a
     *         user or when it could not be written
     */
    default FinalActionWrite writeUndecidedChallenge(String userId, Map<String, Object> fields) {
        if (userId == null || userId.isBlank()) {
            return FinalActionWrite.FAILED;
        }
        ZeroTrustAction inForce = getActionFromHash(userId);
        if (inForce == ZeroTrustAction.BLOCK || inForce == ZeroTrustAction.ESCALATE
                || (inForce == ZeroTrustAction.CHALLENGE && !isTechnicalChallenge(userId))) {
            return FinalActionWrite.KEPT_STRICTER;
        }
        saveAction(userId, ZeroTrustAction.CHALLENGE, fields);
        return FinalActionWrite.APPLIED;
    }

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction);

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash);

    /**
     * Q-12: called for a session that answered the CHALLENGE, before its ALLOW replaces the decision. A CHALLENGE is
     * decided for the user, and the answer of one session proves nothing about another: what the stolen password
     * opened stays stopped when the owner passes the code. So every context but the given one keeps reading CHALLENGE
     * until the CHALLENGE would have lapsed, an answer of another session adds that session, and an administrator's
     * override or the removal of the user's data ends it. Nothing changes for a user who is not challenged.
     * A repository that does not implement this releases the user, as an ALLOW did before.
     */
    default void holdChallengeForOtherSessions(String userId, String contextBindingHash) {
    }

    /** Q-12: when the CHALLENGE still held for other sessions was decided, or null with none held. */
    @Nullable
    default Instant challengeHeldSince(String userId) {
        return null;
    }


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

