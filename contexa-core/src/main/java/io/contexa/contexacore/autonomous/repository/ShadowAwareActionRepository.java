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
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * What SHADOW mode remembers of its decisions. SHADOW decides as ENFORCE does and applies nothing; what it decided still
 * has to answer the user's next requests, or every request of a user would be analysed again where ENFORCE analyses one
 * (the ALLOW in force answers the rest) and the count of model calls, the cost, and the statistics of the trial would no
 * longer be those of ENFORCE.
 * <p>
 * The memory is the store of ENFORCE under other keys ({@link ZeroTrustUserKey#shadow}), so that it keeps the same
 * rules (a stricter decision stays, the same lifetimes) and nothing that enforces a decision reads it: the filters, the
 * gates and the checks keep the repository itself, which holds no decision of SHADOW. A switch to ENFORCE starts with
 * the decisions ENFORCE made.
 * <p>
 * Two forms: {@link #always} is the memory the enforcement handler writes in SHADOW, and {@link #whenNotEnforcing} is
 * what the counting of decisions reads, which is the memory while decisions are not enforced and the repository itself
 * when they are.
 */
public final class ShadowAwareActionRepository implements ZeroTrustActionRepository {

    private final ZeroTrustActionRepository repository;
    private final BooleanSupplier remembering;

    private ShadowAwareActionRepository(ZeroTrustActionRepository repository, BooleanSupplier remembering) {
        this.repository = repository;
        this.remembering = remembering;
    }

    /** The memory of SHADOW itself: every call is made on the shadow keys. */
    public static ShadowAwareActionRepository always(ZeroTrustActionRepository repository) {
        return new ShadowAwareActionRepository(repository, () -> true);
    }

    /** The repository while decisions are enforced and the memory of SHADOW while they are not. */
    public static ShadowAwareActionRepository whenNotEnforcing(ZeroTrustActionRepository repository, BooleanSupplier enforcing) {
        return new ShadowAwareActionRepository(repository, () -> !enforcing.getAsBoolean());
    }

    @Nullable
    private String key(@Nullable String userId) {
        return remembering.getAsBoolean() ? ZeroTrustUserKey.shadow(userId) : userId;
    }

    @Override
    public ZeroTrustAction getCurrentAction(String userId) {
        return repository.getCurrentAction(key(userId));
    }

    @Override
    public ZeroTrustAction getCurrentAction(String userId, String contextBindingHash) {
        return repository.getCurrentAction(key(userId), contextBindingHash);
    }

    @Override
    public ZeroTrustAnalysisData getAnalysisData(String userId) {
        return repository.getAnalysisData(key(userId));
    }

    @Override
    public ZeroTrustAction getActionFromHash(String userId) {
        return repository.getActionFromHash(key(userId));
    }

    @Override
    public ZeroTrustAction getPreviousActionFromHash(String userId) {
        return repository.getPreviousActionFromHash(key(userId));
    }

    @Override
    public ZeroTrustAction getLastVerifiedAction(String userId) {
        return repository.getLastVerifiedAction(key(userId));
    }

    @Override
    @Nullable
    public String decidedContext(String userId) {
        return repository.decidedContext(key(userId));
    }

    @Override
    public boolean isTechnicalChallenge(String userId) {
        return repository.isTechnicalChallenge(key(userId));
    }

    @Override
    public long getBlockMfaFailCount(String userId) {
        return repository.getBlockMfaFailCount(key(userId));
    }

    @Override
    public boolean isStale(String userId, long maxAgeMs) {
        return repository.isStale(key(userId), maxAgeMs);
    }

    @Override
    public boolean isBlockMfaPending(String userId) {
        return repository.isBlockMfaPending(key(userId));
    }

    @Override
    public void setBlockMfaPending(String userId) {
        repository.setBlockMfaPending(key(userId));
    }

    @Override
    public boolean hasEscalateRetry(String userId) {
        return repository.hasEscalateRetry(key(userId));
    }

    @Override
    public void setEscalateRetry(String userId, Duration ttl) {
        repository.setEscalateRetry(key(userId), ttl);
    }

    @Override
    public void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        repository.saveAction(key(userId), action, additionalFields);
    }

    @Override
    public boolean saveFinalAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        return repository.saveFinalAction(key(userId), action, additionalFields);
    }

    @Override
    public FinalActionWrite writeFinalAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        return repository.writeFinalAction(key(userId), action, additionalFields);
    }

    @Override
    public FinalActionWrite writeUndecidedChallenge(String userId, Map<String, Object> fields) {
        return repository.writeUndecidedChallenge(key(userId), fields);
    }

    @Override
    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction) {
        repository.saveActionWithPrevious(key(userId), newAction);
    }

    @Override
    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash) {
        repository.saveActionWithPrevious(key(userId), newAction, contextBindingHash);
    }

    @Override
    public void holdChallengeForOtherSessions(String userId, String contextBindingHash) {
        repository.holdChallengeForOtherSessions(key(userId), contextBindingHash);
    }

    @Override
    @Nullable
    public Instant challengeHeldSince(String userId) {
        return repository.challengeHeldSince(key(userId));
    }

    @Override
    public void setBlockedFlag(String userId) {
        repository.setBlockedFlag(key(userId));
    }

    @Override
    public boolean restoreBlockedFlag(String userId) {
        return repository.restoreBlockedFlag(key(userId));
    }

    @Override
    public void removeBlockedFlag(String userId) {
        repository.removeBlockedFlag(key(userId));
    }

    @Override
    public void clearBlockMfaPending(String userId) {
        repository.clearBlockMfaPending(key(userId));
    }

    @Override
    public long incrementBlockMfaFailCount(String userId) {
        return repository.incrementBlockMfaFailCount(key(userId));
    }

    @Override
    public void removeAllUserData(String userId) {
        repository.removeAllUserData(key(userId));
    }

    @Override
    public void removeAllAgentData(String userId) {
        repository.removeAllAgentData(key(userId));
    }

    @Override
    public void removeLogoutData(String userId) {
        repository.removeLogoutData(key(userId));
    }

    @Override
    public void markDecisionAuditPending(String userId, String contextBindingHash, Duration ttl) {
        repository.markDecisionAuditPending(key(userId), contextBindingHash, ttl);
    }

    @Override
    public boolean isDecisionAuditPending(String userId, String contextBindingHash) {
        return repository.isDecisionAuditPending(key(userId), contextBindingHash);
    }

    @Override
    public void clearDecisionAuditPending(String userId, String contextBindingHash) {
        repository.clearDecisionAuditPending(key(userId), contextBindingHash);
    }

    @Override
    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        repository.approveOverrideAtomically(key(userId), newAction);
    }

    /** The repository carries what a stored ESCALATE ends as; the memory has no setting of its own. */
    @Override
    public void setEscalateTerminalAction(ZeroTrustAction action) {
    }
}
