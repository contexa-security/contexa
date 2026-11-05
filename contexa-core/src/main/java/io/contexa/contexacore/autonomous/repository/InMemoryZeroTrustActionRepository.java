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
import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


/**
 * In-memory implementation of ZeroTrustActionRepository for standalone mode.
 * Uses in-memory key spaces instead of Redis Hash/String operations.
 * <p>
 * QF-47, QF-48 (DD-66): every read answers as ZeroTrustActionRedisRepository answers for the same state. An analysis
 * past its TTL is absent, as its Redis key is, and the sweep removes it; its 24 h last verified record stays as its
 * Redis key does. Outside a request too, a decision past its TTL lapses in both (only an unresolved ESCALATE stays).
 * <p>
 * Z-16 (1-d): the BLOCK MFA verification InMemoryBlockMfaStateStore records is kept here, as the Redis repository's
 * keys hold it beside the user's other BLOCK MFA state, so a logout and the removal of the user's or agents' data take
 * it with them.
 * <p>
 * QF-42: the store keeps at most {@code maxUsers} users. Past it, the users whose last write is the oldest are
 * released first; a user whose state restricts is never released, nor one decided within the decision's TTL.
 * <p>
 * Z-16 (N-1): each kind of state is an {@link ExpiringKeySpace}, whose keys expire as the Redis keys do; the user's
 * lock still makes the writes of one user and a release atomic across them.
 */
@Slf4j
public class InMemoryZeroTrustActionRepository implements ZeroTrustActionRepository, ExpiringStateStore {

    private final ExpiringKeySpace<AnalysisEntry> analyses;

    /** Set by a final write the calling thread made that a stricter action in effect kept out (W5-3). */
    private final ThreadLocal<Boolean> finalWriteKeptStricter = new ThreadLocal<>();
    private final ExpiringKeySpace<ZeroTrustAction> lastVerified;
    private final Set<String> blockedUsers = ConcurrentHashMap.newKeySet();
    private static final Duration MFA_PENDING_TTL = Duration.ofMinutes(10);
    private static final Duration DEFAULT_FAIL_COUNT_TTL = Duration.ofHours(24);
    private static final Duration LAST_VERIFIED_ACTION_TTL = Duration.ofHours(24);
    /** A decision without a TTL (BLOCK, PENDING_ANALYSIS) is held until it is replaced or removed. */
    private static final Duration NO_TTL = Duration.ofMillis(Long.MAX_VALUE);
    /**
     * QF-42: a user's write record lasts past any clock; its expiry, this span after the write, orders the bound on
     * users, the oldest write first.
     */
    private static final Duration WRITE_ORDER_SPAN = Duration.ofMillis(Long.MAX_VALUE / 2);

    /** QF-42: the default bound on users is the users of an estimated size that a share of the maximum heap holds. */
    static final long DEFAULT_HEAP_SHARE_DIVISOR = 20;
    static final long ESTIMATED_BYTES_PER_USER = 2_048;
    static final int MIN_DEFAULT_MAX_USERS = 1_000;
    static final int MAX_DEFAULT_MAX_USERS = 1_000_000;

    private final ExpiringKeySpace<Long> mfaFailCounts;
    private final ExpiringKeySpace<Boolean> mfaPending;
    private final ExpiringKeySpace<Boolean> escalateRetries;
    private final ConcurrentHashMap<String, ReentrantLock> userLocks = new ConcurrentHashMap<>();
    /** Each user's decision audit markers, by context. */
    private final ConcurrentHashMap<String, ExpiringKeySpace<Boolean>> decisionAuditPending = new ConcurrentHashMap<>();
    private static final String DECISION_AUDIT_NO_CONTEXT = "no-context";
    /** Z-16 (1-d): each BLOCK MFA verification, with when it lapses. */
    private final ExpiringKeySpace<Instant> blockMfaVerifiedUntil;

    /**
     * QF-42: when each user's state was last written, bounded by {@link #maxUsers}: past it the oldest write goes first,
     * releasing the user ({@link #releaseUser}), and a user {@link #releasable} keeps out of it never goes.
     */
    private final ExpiringKeySpace<Long> lastWrittenMs;

    private final Duration failCountTtl;
    private final Clock clock;
    private final int maxUsers;

    /** What a stored ESCALATE is replaced with when it is read; null keeps it. */
    private volatile ZeroTrustAction escalateReplacement;

    public InMemoryZeroTrustActionRepository() {
        this(DEFAULT_FAIL_COUNT_TTL, Clock.systemUTC());
    }

    /** QF-42: keeps at most {@code maxUsers} users; not positive, the bound derived from the maximum heap. */
    public InMemoryZeroTrustActionRepository(int maxUsers) {
        this(DEFAULT_FAIL_COUNT_TTL, Clock.systemUTC(), maxUsers);
    }

    public InMemoryZeroTrustActionRepository(Duration failCountTtl) {
        this(failCountTtl, Clock.systemUTC());
    }

    public InMemoryZeroTrustActionRepository(Duration failCountTtl, Clock clock) {
        this(failCountTtl, clock, 0);
    }

    public InMemoryZeroTrustActionRepository(Duration failCountTtl, Clock clock, int maxUsers) {
        this.failCountTtl = Objects.requireNonNull(failCountTtl, "failCountTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxUsers = maxUsers > 0 ? maxUsers : defaultMaxUsers(Runtime.getRuntime().maxMemory());
        this.analyses = ExpiringKeySpace.<AnalysisEntry>builder(clock).build();
        this.lastVerified = ExpiringKeySpace.<ZeroTrustAction>builder(clock).ttl(LAST_VERIFIED_ACTION_TTL).build();
        this.mfaFailCounts = ExpiringKeySpace.<Long>builder(clock).ttl(failCountTtl).build();
        this.mfaPending = ExpiringKeySpace.<Boolean>builder(clock).ttl(MFA_PENDING_TTL).build();
        this.escalateRetries = ExpiringKeySpace.<Boolean>builder(clock).build();
        this.blockMfaVerifiedUntil = ExpiringKeySpace.<Instant>builder(clock).build();
        this.lastWrittenMs = ExpiringKeySpace.<Long>builder(clock)
                .ttl(WRITE_ORDER_SPAN)
                .bound(this.maxUsers)
                .evictable(this::releasable)
                .evictWith(this::releaseUser)
                .build();
    }

    /**
     * QF-42: the default bound on users for a maximum heap of {@code maxHeapBytes}: a twentieth of the heap (5 %) at an
     * estimated 2 KiB a user, between 1,000 and 1,000,000. A user past the TTL of its decision keeps its last verified
     * record, lock and write time (about 0.4 KiB); a user decided within the TTL also keeps the analysis with the
     * model's reasoning (1-4 KiB). A 512 MiB heap keeps 13,107 users, 2 GiB 52,428, 8 GiB 209,715; a JVM without a
     * heap limit the most.
     */
    static int defaultMaxUsers(long maxHeapBytes) {
        long users = maxHeapBytes / DEFAULT_HEAP_SHARE_DIVISOR / ESTIMATED_BYTES_PER_USER;
        return (int) Math.max(MIN_DEFAULT_MAX_USERS, Math.min(MAX_DEFAULT_MAX_USERS, users));
    }

    /** The most users the store keeps (QF-42). */
    public int maxUsers() {
        return maxUsers;
    }

    @Override
    public void setEscalateTerminalAction(ZeroTrustAction action) {
        this.escalateReplacement = ZeroTrustActionPrecedence.storedEscalateReplacement(action);
    }

    @Override
    public ZeroTrustAction getCurrentAction(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        // As the Redis repository, a read made for a request checks the request's context binding (QF-47).
        try {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
                return getCurrentAction(userId,
                        SessionFingerprintUtil.generateContextBindingHash(attributes.getRequest()));
            }
        } catch (Exception e) {
            log.error("[InMemoryZTARepository] Failed to get request context, falling back to non-context check: userId={}", userId, e);
        }

        if (blockedUsers.contains(userId)) {
            return ZeroTrustAction.BLOCK;
        }

        AnalysisEntry entry = settledAnalysis(userId);
        if (entry != null) {
            return ZeroTrustAction.fromString(entry.action);
        }
        // Outside a request the Redis repository answers with the 24 h last verified action, which would keep an
        // ALLOW or CHALLENGE in force a day past its TTL; here it lapses as in a request (QF-47).
        return unresolvedEscalationOrPending(userId);
    }

    @Override
    public ZeroTrustAction getCurrentAction(String userId, String contextBindingHash) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        if (blockedUsers.contains(userId)) {
            return ZeroTrustAction.BLOCK;
        }

        AnalysisEntry entry = settledAnalysis(userId);
        if (entry == null) {
            // QF-47: without an analysis in its TTL only an unresolved ESCALATE stays, as in the Redis repository.
            return unresolvedEscalationOrPending(userId);
        }
        ZeroTrustAction action = ZeroTrustAction.fromString(entry.action);
        if (requiresFreshAnalysis(action, contextBindingHash, entry.contextBindingHash)) {
            log.error("[InMemoryZTARepository] Context binding hash mismatch detected: userId={}, action={}", userId, action);
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
        return action;
    }

    @Override
    public ZeroTrustAnalysisData getAnalysisData(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return ZeroTrustAnalysisData.pending();
        }

        AnalysisEntry entry = settledAnalysis(userId);
        if (entry == null) {
            return ZeroTrustAnalysisData.pending();
        }

        return new ZeroTrustAnalysisData(
                entry.action,
                entry.riskScore,
                entry.confidence,
                entry.threatEvidence,
                entry.analysisDepth,
                entry.updatedAt,
                entry.reasoning,
                entry.reasoningSummary,
                entry.requestId,
                entry.contextBindingHash,
                entry.llmProposedAction
        );
    }

    @Override
    public ZeroTrustAction getActionFromHash(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return null;
        }
        AnalysisEntry entry = settledAnalysis(userId);
        return entry != null ? ZeroTrustAction.fromString(entry.action) : null;
    }

    @Override
    public ZeroTrustAction getPreviousActionFromHash(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return null;
        }
        AnalysisEntry entry = liveAnalysis(userId);
        return entry != null && entry.previousAction != null
                ? ZeroTrustAction.fromString(entry.previousAction) : null;
    }

    @Override
    public ZeroTrustAction getLastVerifiedAction(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return null;
        }
        return lastVerified.get(userId);
    }

    @Override
    public long getBlockMfaFailCount(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return 0;
        }
        Long count = mfaFailCounts.get(userId);
        return count != null ? count : 0;
    }

    @Override
    public boolean isStale(String userId, long maxAgeMs) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return true;
        }
        AnalysisEntry entry = liveAnalysis(userId);
        if (entry == null || entry.updatedAt == null) {
            return true;
        }
        try {
            Instant updated = Instant.parse(entry.updatedAt);
            return Instant.now().toEpochMilli() - updated.toEpochMilli() > maxAgeMs;
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public boolean isBlockMfaPending(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return false;
        }
        return mfaPending.containsKey(userId);
    }

    @Override
    public void setBlockMfaPending(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return;
        }
        mfaPending.put(userId, Boolean.TRUE);
        recordWrite(userId);
    }

    @Override
    public boolean hasEscalateRetry(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return false;
        }
        return escalateRetries.containsKey(userId);
    }

    /** Sets the retry unless one is in force, as the Redis repository sets its key only while none exists. */
    @Override
    public void setEscalateRetry(String userId, Duration ttl) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || ttl == null) {
            return;
        }
        escalateRetries.putIfAbsent(userId, Boolean.TRUE, ttl);
        recordWrite(userId);
    }

    @Override
    public void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || action == null) {
            return;
        }

        ReentrantLock lock = lockUser(userId);
        try {
            AnalysisEntry existing = liveAnalysis(userId);
            String previousAction = existing != null ? existing.action : null;

            AnalysisEntry entry = new AnalysisEntry();
            entry.action = action.name();
            entry.previousAction = previousAction;
            entry.updatedAt = Instant.now().toString();

            if (additionalFields != null) {
                Object threatEvidence = additionalFields.get("threatEvidence");
                if (threatEvidence != null) {
                    entry.threatEvidence = threatEvidence.toString();
                }
                Object riskScore = additionalFields.get("riskScore");
                if (riskScore instanceof Number num) {
                    entry.riskScore = num.doubleValue();
                }
                Object confidence = additionalFields.get("confidence");
                if (confidence instanceof Number num) {
                    entry.confidence = num.doubleValue();
                }
                Object analysisDepth = additionalFields.get("analysisDepth");
                if (analysisDepth instanceof Number num) {
                    entry.analysisDepth = num.intValue();
                }
                Object reasoning = additionalFields.get("reasoning");
                if (reasoning != null) {
                    entry.reasoning = reasoning.toString();
                }
                Object reasoningSummary = additionalFields.get("reasoningSummary");
                if (reasoningSummary != null) {
                    entry.reasoningSummary = reasoningSummary.toString();
                }
                Object requestId = additionalFields.get("requestId");
                if (requestId != null) {
                    entry.requestId = requestId.toString();
                }
                Object contextBindingHash = additionalFields.get("contextBindingHash");
                if (contextBindingHash != null) {
                    entry.contextBindingHash = contextBindingHash.toString();
                }
                Object llmProposedAction = additionalFields.get("llmProposedAction");
                if (llmProposedAction != null) {
                    entry.llmProposedAction = llmProposedAction.toString();
                }
            }

            analyses.put(userId, entry, ttlOf(action));
            putLastVerified(userId, action);
        } finally {
            lock.unlock();
        }
        recordWrite(userId);
    }

    /**
     * Stores the final analysis result unless it is less strict than an active user-level
     * BLOCK, CHALLENGE or ESCALATE, whichever session it was analysed for. A BLOCK is active
     * while its analysis says so or its flag stands (the analysis may have expired). The stricter
     * action then stays in effect and the write is reported as applied. Z-16 (1-c): as in the Redis
     * repository, a decision without its user, its action, or the observation and processing generation
     * that bind it to its audit record is not written and the write fails.
     */
    @Override
    public boolean saveFinalAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || action == null || !boundToItsObservation(additionalFields)) {
            return false;
        }

        ReentrantLock lock = lockUser(userId);
        try {
            AnalysisEntry active = liveAnalysis(userId);
            boolean analysisKeeps = active != null
                    && ZeroTrustActionPrecedence.keepsActiveRestriction(ZeroTrustAction.fromString(active.action), action);
            boolean flagKeeps = blockedUsers.contains(userId)
                    && ZeroTrustActionPrecedence.keepsActiveRestriction(ZeroTrustAction.BLOCK, action);
            boolean keepsActiveRestriction = analysisKeeps || flagKeeps;
            if (!keepsActiveRestriction) {
                saveAction(userId, action, additionalFields);
            } else {
                finalWriteKeptStricter.set(Boolean.TRUE);
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    private static boolean boundToItsObservation(Map<String, Object> fields) {
        return fields != null && hasText(fields.get("observationId")) && hasText(fields.get("processingGeneration"));
    }

    private static boolean hasText(Object value) {
        return value != null && !value.toString().isBlank();
    }

    @Override
    public FinalActionWrite writeFinalAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        userId = ZeroTrustUserKey.of(userId);
        finalWriteKeptStricter.remove();
        try {
            if (!saveFinalAction(userId, action, additionalFields)) {
                return FinalActionWrite.FAILED;
            }
            return Boolean.TRUE.equals(finalWriteKeptStricter.get())
                    ? FinalActionWrite.KEPT_STRICTER : FinalActionWrite.APPLIED;
        } finally {
            finalWriteKeptStricter.remove();
        }
    }

    @Override
    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction) {
        userId = ZeroTrustUserKey.of(userId);
        saveActionWithPrevious(userId, newAction, null);
    }

    /**
     * QF-48: as the Redis repository, the new action keeps every field of the analysis in its TTL (one past it leaves
     * nothing) with its action as the previous one, PENDING_ANALYSIS without one; a given context binding replaces the
     * kept one.
     */
    @Override
    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || newAction == null) {
            return;
        }

        ReentrantLock lock = lockUser(userId);
        try {
            AnalysisEntry existing = liveAnalysis(userId);
            AnalysisEntry entry = existing != null ? existing.copy() : new AnalysisEntry();
            entry.previousAction = existing != null && existing.action != null
                    ? existing.action : ZeroTrustAction.PENDING_ANALYSIS.name();
            entry.action = newAction.name();
            entry.updatedAt = Instant.now().toString();
            if (contextBindingHash != null) {
                entry.contextBindingHash = contextBindingHash;
            }
            analyses.put(userId, entry, ttlOf(newAction));
            putLastVerified(userId, newAction);
        } finally {
            lock.unlock();
        }
        recordWrite(userId);
    }

    @Override
    public void setBlockedFlag(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return;
        }
        ReentrantLock lock = lockUser(userId);
        try {
            blockedUsers.add(userId);
        } finally {
            lock.unlock();
        }
        recordWrite(userId);
    }

    @Override
    public void removeBlockedFlag(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (!isBlank(userId)) {
            blockedUsers.remove(userId);
        }
    }

    @Override
    public void clearBlockMfaPending(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (!isBlank(userId)) {
            mfaPending.remove(userId);
        }
    }

    /** Each failure keeps the count another full TTL, as the Redis repository sets the key's TTL on every increment. */
    @Override
    public long incrementBlockMfaFailCount(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return 0;
        }
        Long count = mfaFailCounts.compute(userId, (key, held) -> held != null ? held + 1 : 1L);
        recordWrite(userId);
        return count;
    }

    /**
     * Clears the user's decision and BLOCK MFA state, as the Redis script does, unless it restricts: the BLOCK flag, a
     * last verified BLOCK, an analysis in its TTL that restricts, or an unresolved ESCALATE (it reads as ESCALATE). The
     * escalate retry and decision audit markers stay until they expire, as their Redis keys do.
     */
    @Override
    public void removeLogoutData(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return;
        }
        ReentrantLock lock = lockUser(userId);
        try {
            if (!keptOnLogout(userId)) {
                analyses.remove(userId);
                lastVerified.remove(userId);
                blockedUsers.remove(userId);
                mfaPending.remove(userId);
                mfaFailCounts.remove(userId);
                blockMfaVerifiedUntil.remove(userId);
            }
        } finally {
            lock.unlock();
        }
        retireLockIfUnused(userId);
    }

    private boolean keptOnLogout(String userId) {
        if (blockedUsers.contains(userId) || getLastVerifiedAction(userId) == ZeroTrustAction.BLOCK) {
            return true;
        }
        AnalysisEntry analysis = liveAnalysis(userId);
        return analysis != null
                ? ZeroTrustAction.fromString(analysis.action).isAccessRestricted()
                : getLastVerifiedAction(userId) == ZeroTrustAction.ESCALATE;
    }

    @Override
    public void removeAllUserData(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return;
        }
        analyses.remove(userId);
        lastVerified.remove(userId);
        blockedUsers.remove(userId);
        mfaFailCounts.remove(userId);
        mfaPending.remove(userId);
        escalateRetries.remove(userId);
        decisionAuditPending.remove(userId);
        blockMfaVerifiedUntil.remove(userId);
        lastWrittenMs.remove(userId);
        retireLockIfUnused(userId);
    }

    @Override
    public void removeAllAgentData(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return;
        }
        String agentKeys = userId + LearningSubject.AGENT_KEY;
        Predicate<String> agentsOfTheUser = key -> key.startsWith(agentKeys);
        analyses.removeIf(agentsOfTheUser);
        lastVerified.removeIf(agentsOfTheUser);
        blockedUsers.removeIf(agentsOfTheUser);
        mfaFailCounts.removeIf(agentsOfTheUser);
        mfaPending.removeIf(agentsOfTheUser);
        escalateRetries.removeIf(agentsOfTheUser);
        decisionAuditPending.keySet().removeIf(agentsOfTheUser);
        blockMfaVerifiedUntil.removeIf(agentsOfTheUser);
        lastWrittenMs.removeIf(agentsOfTheUser);
        userLocks.keySet().stream().filter(agentsOfTheUser).toList()
                .forEach(this::retireLockIfUnused);
    }

    /**
     * Z-16 (1-d): records the user's BLOCK MFA verification for {@code ttl}, for InMemoryBlockMfaStateStore, as its
     * Redis key sits beside the user's other BLOCK MFA state: a logout and the removal of the user's or agents' data
     * remove it as they remove the rest.
     */
    public void setBlockMfaVerified(String userId, Duration ttl) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || ttl == null) {
            return;
        }
        blockMfaVerifiedUntil.put(userId, clock.instant().plus(ttl), ttl);
        recordWrite(userId);
    }

    /** Z-16 (1-d): when the user's BLOCK MFA verification lapses; null without one in force. */
    public Instant getBlockMfaVerifiedUntil(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return null;
        }
        return blockMfaVerifiedUntil.get(userId);
    }

    /** Z-16 (1-d): removes the user's BLOCK MFA verification. */
    public void clearBlockMfaVerified(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        if (!isBlank(userId)) {
            blockMfaVerifiedUntil.remove(userId);
        }
    }

    @Override
    public void markDecisionAuditPending(String userId, String contextBindingHash, Duration ttl) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        String contextKey = decisionAuditContextKey(contextBindingHash);
        // Written within the user's entry, so the sweep cannot release the user's markers between lookup and write.
        decisionAuditPending.compute(userId, (key, contexts) -> {
            ExpiringKeySpace<Boolean> pending = contexts != null
                    ? contexts : ExpiringKeySpace.<Boolean>builder(clock).build();
            pending.put(contextKey, Boolean.TRUE, ttl);
            return pending;
        });
        recordWrite(userId);
    }

    @Override
    public boolean isDecisionAuditPending(String userId, String contextBindingHash) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return false;
        }
        ExpiringKeySpace<Boolean> contexts = decisionAuditPending.get(userId);
        return contexts != null && contexts.containsKey(decisionAuditContextKey(contextBindingHash));
    }

    @Override
    public void clearDecisionAuditPending(String userId, String contextBindingHash) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId)) {
            return;
        }
        ExpiringKeySpace<Boolean> contexts = decisionAuditPending.get(userId);
        if (contexts != null) {
            contexts.remove(decisionAuditContextKey(contextBindingHash));
        }
    }

    /**
     * Releases what no read can return any more: an analysis past its TTL (QF-48: it is absent to every read, as its
     * Redis key), a last verified record after its 24 h, MFA counters, retry and audit markers past their time.
     * Decisions without a TTL (BLOCK) stay. QF-42: a user's lock goes once nothing of the user is left and no thread
     * holds it, and the users past the bound are released. The sweep takes no lock and makes none: a key space removes
     * an entry only while it is still the one past its time, so a decision written meanwhile stays.
     */
    @Override
    public void removeExpiredEntries() {
        lastVerified.removeExpired();
        analyses.removeExpired();
        mfaFailCounts.removeExpired();
        mfaPending.removeExpired();
        escalateRetries.removeExpired();
        blockMfaVerifiedUntil.removeExpired();
        for (String userId : decisionAuditPending.keySet()) {
            decisionAuditPending.computeIfPresent(userId, (key, contexts) -> withoutExpiredMarkers(contexts));
        }
        countWrittenUsers();
        // Also keeps the bound: the users past it that may go by now are released.
        lastWrittenMs.removeExpired();
        userLocks.keySet().forEach(this::retireLockIfUnused);
    }

    /**
     * Forgets the write time of a user with nothing left, and counts a user whose decision has none (a sweep that ran
     * between the decision and its write time) from now.
     */
    private void countWrittenUsers() {
        lastWrittenMs.forEach((userId, writtenMs) -> {
            if (!holdsStateFor(userId)) {
                lastWrittenMs.remove(userId, writtenMs);
            }
        });
        long nowMs = clock.millis();
        analyses.forEach((userId, analysis) -> lastWrittenMs.putIfAbsent(userId, nowMs));
        lastVerified.forEach((userId, action) -> lastWrittenMs.putIfAbsent(userId, nowMs));
    }

    /** QF-42: the user's latest write; a user past the bound releases the users written the longest ago. */
    private void recordWrite(String userId) {
        lastWrittenMs.put(userId, clock.millis());
    }

    /**
     * QF-42: releases a user the bound chose, the oldest write first; the key space has skipped the user already if it
     * was written since it was chosen. A user whose state restricts ({@link #restricts}) is never released, nor one
     * decided within the decision's TTL (an ALLOW's 15 s): releasing it would only bring the same analysis again; the
     * store holds more while only such users are left. A user in use by another thread is skipped too.
     */
    private void releaseUser(String userId) {
        ReentrantLock lock = tryLockUser(userId);
        if (lock == null) {
            return;
        }
        try {
            Long writtenMs = lastWrittenMs.get(userId);
            if (writtenMs != null && releasable(userId)) {
                release(userId, writtenMs);
            }
        } finally {
            lock.unlock();
        }
        retireLockIfUnused(userId);
    }

    /**
     * Removes what is left of a user nothing of whom restricts, under the user's lock: entries that allow and entries
     * past their time. Each removal names the entry it saw, so an entry a writer without the user's lock adds meanwhile
     * is new and stays.
     */
    private void release(String userId, long writtenMs) {
        AnalysisEntry analysis = analyses.get(userId);
        if (analysis != null) {
            analyses.remove(userId, analysis);
        }
        ZeroTrustAction verified = lastVerified.get(userId);
        if (verified != null) {
            lastVerified.remove(userId, verified);
        }
        // A read removes a value past its time and leaves one in force.
        mfaFailCounts.containsKey(userId);
        mfaPending.containsKey(userId);
        escalateRetries.containsKey(userId);
        decisionAuditPending.computeIfPresent(userId, (key, contexts) -> withoutExpiredMarkers(contexts));
        Instant mfaVerified = blockMfaVerifiedUntil.get(userId);
        if (mfaVerified != null) {
            blockMfaVerifiedUntil.remove(userId, mfaVerified);
        }
        lastWrittenMs.remove(userId, writtenMs);
    }

    /** Whether the bound may release the user: nothing restricts and no decision with a TTL is in force. */
    private boolean releasable(String userId) {
        long analysisExpiresAtMs = analyses.expiresAtMs(userId);
        boolean decidedWithinTtl = analysisExpiresAtMs != 0 && analysisExpiresAtMs != Long.MAX_VALUE;
        return !decidedWithinTtl && !restricts(userId);
    }

    /**
     * Whether the user's state restricts, now or until it is resolved: the BLOCK flag, an analysis in its TTL that
     * restricts, a last verified ESCALATE (it reads as ESCALATE until resolved) or BLOCK (a logout keeps it), a pending
     * BLOCK MFA or its failure count, an ESCALATE retry or a decision audit marker in force. The bound on users never
     * releases such a user.
     */
    private boolean restricts(String userId) {
        if (blockedUsers.contains(userId)) {
            return true;
        }
        AnalysisEntry analysis = liveAnalysis(userId);
        if (analysis != null && ZeroTrustAction.fromString(analysis.action).isAccessRestricted()) {
            return true;
        }
        ZeroTrustAction verified = getLastVerifiedAction(userId);
        if (verified == ZeroTrustAction.ESCALATE || verified == ZeroTrustAction.BLOCK) {
            return true;
        }
        if (mfaPending.containsKey(userId) || mfaFailCounts.containsKey(userId) || escalateRetries.containsKey(userId)) {
            return true;
        }
        ExpiringKeySpace<Boolean> markers = decisionAuditPending.get(userId);
        return markers != null && !markers.keys().isEmpty();
    }

    /**
     * Takes the user's lock. The sweep may retire a lock that a thread looked up but had not taken yet; that thread
     * then takes the lock in the map instead, so two threads never hold different locks of one user (QF-42).
     */
    ReentrantLock lockUser(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        while (true) {
            ReentrantLock lock = userLocks.computeIfAbsent(userId, key -> new ReentrantLock());
            lock.lock();
            if (userLocks.get(userId) == lock) {
                return lock;
            }
            lock.unlock();
        }
    }

    /** The user's lock when it is free now and not this thread's already, as {@link #lockUser} takes it; else null. */
    private ReentrantLock tryLockUser(String userId) {
        ReentrantLock lock = userLocks.computeIfAbsent(userId, key -> new ReentrantLock());
        if (lock.isHeldByCurrentThread() || !lock.tryLock()) {
            return null;
        }
        if (userLocks.get(userId) != lock) {
            lock.unlock();
            return null;
        }
        return lock;
    }

    /**
     * Removes the user's lock when nothing of the user is left and no thread holds it (QF-42). It is removed while this
     * thread alone holds it, so a thread waiting for it takes the user's next lock ({@link #lockUser}).
     */
    private void retireLockIfUnused(String userId) {
        ReentrantLock lock = userLocks.get(userId);
        if (lock == null || holdsStateFor(userId) || !lock.tryLock()) {
            return;
        }
        try {
            if (lock.getHoldCount() == 1 && !holdsStateFor(userId)) {
                userLocks.remove(userId, lock);
            }
        } finally {
            lock.unlock();
        }
    }

    /** The user's markers without those past their time; null once none is left. */
    private static ExpiringKeySpace<Boolean> withoutExpiredMarkers(ExpiringKeySpace<Boolean> contexts) {
        contexts.removeExpired();
        return contexts.size() == 0 ? null : contexts;
    }

    private String decisionAuditContextKey(String contextBindingHash) {
        return contextBindingHash == null || contextBindingHash.isBlank()
                ? DECISION_AUDIT_NO_CONTEXT
                : contextBindingHash;
    }

    /**
     * QF-48: as the Redis repository, the analysis keeps every field it had in its TTL and its previous action; the
     * BLOCK flag goes and the new action is the last verified one.
     */
    @Override
    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        userId = ZeroTrustUserKey.of(userId);
        if (isBlank(userId) || newAction == null) {
            return;
        }

        ReentrantLock lock = lockUser(userId);
        try {
            blockedUsers.remove(userId);
            AnalysisEntry existing = liveAnalysis(userId);
            AnalysisEntry entry = existing != null ? existing.copy() : new AnalysisEntry();
            entry.action = newAction.name();
            entry.updatedAt = Instant.now().toString();
            analyses.put(userId, entry, ttlOf(newAction));
            putLastVerified(userId, newAction);
        } finally {
            lock.unlock();
        }
        recordWrite(userId);
    }

    /** QF-48: the user's analysis in its TTL; past it the analysis is absent, as its Redis key is. */
    private AnalysisEntry liveAnalysis(String userId) {
        AnalysisEntry entry = analyses.get(userId);
        return entry != null && entry.action != null ? entry : null;
    }

    private static Duration ttlOf(ZeroTrustAction action) {
        Duration ttl = action.getDefaultTtl();
        return ttl != null ? ttl : NO_TTL;
    }

    private void putLastVerified(String userId, ZeroTrustAction action) {
        lastVerified.put(userId, action);
    }

    private static boolean isBlank(String userId) {
        return userId == null || userId.isBlank();
    }

    // An ESCALATE whose TTL ends without resolution keeps reading as ESCALATE through its 24 h last-verified
    // record, so the access filter promotes it to BLOCK; every other expired action reads as PENDING_ANALYSIS.
    // With a replacement set it ends here instead, and nothing promotes it.
    private ZeroTrustAction unresolvedEscalationOrPending(String userId) {
        if (getLastVerifiedAction(userId) != ZeroTrustAction.ESCALATE) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
        ZeroTrustAction replacement = escalateReplacement;
        if (replacement == null) {
            return ZeroTrustAction.ESCALATE;
        }
        replaceStoredEscalate(userId, replacement);
        return replacement;
    }

    /** The user's analysis for a reader: an ESCALATE in it ends first, when a replacement is set. */
    private AnalysisEntry settledAnalysis(String userId) {
        AnalysisEntry entry = liveAnalysis(userId);
        ZeroTrustAction replacement = escalateReplacement;
        if (replacement == null || entry == null || ZeroTrustAction.fromString(entry.action) != ZeroTrustAction.ESCALATE) {
            return entry;
        }
        replaceStoredEscalate(userId, replacement);
        return liveAnalysis(userId);
    }

    /**
     * Ends the ESCALATE left in the store as the replacement, with the replacement's own TTL; the analysis stays with it
     * (a step-up learns the request it stopped from its id). Under the user's lock, as the Redis repository's script,
     * any other action stored by now, or a BLOCK flag, keeps the store as it is.
     */
    private void replaceStoredEscalate(String userId, ZeroTrustAction replacement) {
        ReentrantLock lock = lockUser(userId);
        try {
            AnalysisEntry stored = liveAnalysis(userId);
            boolean escalate = stored != null
                    ? ZeroTrustAction.fromString(stored.action) == ZeroTrustAction.ESCALATE
                    : getLastVerifiedAction(userId) == ZeroTrustAction.ESCALATE;
            if (!escalate || blockedUsers.contains(userId)) {
                return;
            }
            AnalysisEntry entry = stored != null ? stored.copy() : new AnalysisEntry();
            entry.previousAction = stored != null ? stored.action : null;
            entry.action = replacement.name();
            entry.updatedAt = Instant.now().toString();
            analyses.put(userId, entry, ttlOf(replacement));
            putLastVerified(userId, replacement);
        } finally {
            lock.unlock();
        }
        recordWrite(userId);
        log.warn("[InMemoryZTARepository] Stored ESCALATE ended: userId={}, action={}", userId, replacement);
    }

    private static class AnalysisEntry {
        String action;
        String previousAction;
        Double riskScore;
        Double confidence;
        String threatEvidence;
        Integer analysisDepth;
        String updatedAt;
        String reasoning;
        String reasoningSummary;
        String requestId;
        String contextBindingHash;
        String llmProposedAction;

        /** Every field, as the Redis repository reads the whole analysis hash before it rewrites it. */
        AnalysisEntry copy() {
            AnalysisEntry copy = new AnalysisEntry();
            copy.action = action;
            copy.previousAction = previousAction;
            copy.riskScore = riskScore;
            copy.confidence = confidence;
            copy.threatEvidence = threatEvidence;
            copy.analysisDepth = analysisDepth;
            copy.updatedAt = updatedAt;
            copy.reasoning = reasoning;
            copy.reasoningSummary = reasoningSummary;
            copy.requestId = requestId;
            copy.contextBindingHash = contextBindingHash;
            copy.llmProposedAction = llmProposedAction;
            return copy;
        }
    }

    private boolean requiresFreshAnalysis(ZeroTrustAction action, String requestedContextHash, String storedContextHash) {
        return ZeroTrustActionPrecedence.isContextBound(action)
                && requestedContextHash != null
                && storedContextHash != null
                && !storedContextHash.equals(requestedContextHash);
    }

    boolean holdsStateFor(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        return analyses.holds(userId) || lastVerified.holds(userId)
                || mfaPending.holds(userId) || escalateRetries.holds(userId)
                || mfaFailCounts.holds(userId) || blockedUsers.contains(userId)
                || decisionAuditPending.containsKey(userId) || blockMfaVerifiedUntil.holds(userId);
    }

    boolean holdsLastVerifiedFor(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        return lastVerified.holds(userId);
    }

    boolean holdsLockFor(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        return userLocks.containsKey(userId);
    }

    boolean holdsAnalysisFor(String userId) {
        userId = ZeroTrustUserKey.of(userId);
        return analyses.holds(userId);
    }

    /** How many users the bound counts. */
    int userCount() {
        return lastWrittenMs.size();
    }
}
