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
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * In-memory implementation of ZeroTrustActionRepository for standalone mode.
 * Uses ConcurrentHashMap instead of Redis Hash/String operations.
 */
@Slf4j
public class InMemoryZeroTrustActionRepository implements ZeroTrustActionRepository {

    private final ConcurrentHashMap<String, AnalysisEntry> analysisStore = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ActionEntry> lastVerifiedStore = new ConcurrentHashMap<>();
    private final Set<String> blockedUsers = ConcurrentHashMap.newKeySet();
    private static final Duration MFA_PENDING_TTL = Duration.ofMinutes(10);
    private static final Duration DEFAULT_FAIL_COUNT_TTL = Duration.ofHours(24);

    private final ConcurrentHashMap<String, FailCountEntry> mfaFailCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> mfaPendingExpiry = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> escalateRetries = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> userLocks = new ConcurrentHashMap<>();

    private final Duration failCountTtl;
    private final java.time.Clock clock;

    public InMemoryZeroTrustActionRepository() {
        this(DEFAULT_FAIL_COUNT_TTL, java.time.Clock.systemUTC());
    }

    public InMemoryZeroTrustActionRepository(Duration failCountTtl) {
        this(failCountTtl, java.time.Clock.systemUTC());
    }

    public InMemoryZeroTrustActionRepository(Duration failCountTtl, java.time.Clock clock) {
        this.failCountTtl = java.util.Objects.requireNonNull(failCountTtl, "failCountTtl");
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
    }

    @Override
    public ZeroTrustAction getCurrentAction(String userId) {
        if (userId == null) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        if (blockedUsers.contains(userId)) {
            return ZeroTrustAction.BLOCK;
        }

        AnalysisEntry entry = analysisStore.get(userId);
        if (entry != null && entry.action != null) {
            ZeroTrustAction action = ZeroTrustAction.fromString(entry.action);
            if (isExpired(entry)) {
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
            return action;
        }

        ActionEntry lastAction = lastVerifiedStore.get(userId);
        if (lastAction != null && !isExpired(lastAction)) {
            return ZeroTrustAction.fromString(lastAction.action);
        }

        return ZeroTrustAction.PENDING_ANALYSIS;
    }

    @Override
    public ZeroTrustAction getCurrentAction(String userId, String contextBindingHash) {
        if (userId == null) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        if (blockedUsers.contains(userId)) {
            return ZeroTrustAction.BLOCK;
        }

        AnalysisEntry entry = analysisStore.get(userId);
        if (entry != null && entry.action != null) {
            ZeroTrustAction action = ZeroTrustAction.fromString(entry.action);
            if (isExpired(entry)) {
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
            if (requiresFreshAnalysis(action, contextBindingHash, entry.contextBindingHash)) {
                log.error("[InMemoryZTARepository] Context binding hash mismatch detected: userId={}, action={}", userId, action);
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
            return action;
        }

        ActionEntry lastAction = lastVerifiedStore.get(userId);
        if (lastAction != null && !isExpired(lastAction)) {
            ZeroTrustAction action = ZeroTrustAction.fromString(lastAction.action);
            if (requiresFreshAnalysis(action, contextBindingHash, lastAction.contextBindingHash)) {
                log.error("[InMemoryZTARepository] Last verified context binding hash mismatch: userId={}, action={}", userId, action);
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
            return action;
        }

        return ZeroTrustAction.PENDING_ANALYSIS;
    }

    @Override
    public ZeroTrustAnalysisData getAnalysisData(String userId) {
        if (userId == null) {
            return ZeroTrustAnalysisData.pending();
        }

        AnalysisEntry entry = analysisStore.get(userId);
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
        if (userId == null) {
            return null;
        }
        AnalysisEntry entry = analysisStore.get(userId);
        return entry != null && entry.action != null ? ZeroTrustAction.fromString(entry.action) : null;
    }

    @Override
    public ZeroTrustAction getPreviousActionFromHash(String userId) {
        if (userId == null) {
            return null;
        }
        AnalysisEntry entry = analysisStore.get(userId);
        return entry != null && entry.previousAction != null
                ? ZeroTrustAction.fromString(entry.previousAction) : null;
    }

    @Override
    public ZeroTrustAction getLastVerifiedAction(String userId) {
        if (userId == null) {
            return null;
        }
        ActionEntry entry = lastVerifiedStore.get(userId);
        if (entry != null && !isExpired(entry)) {
            return ZeroTrustAction.fromString(entry.action);
        }
        return null;
    }

    @Override
    public long getBlockMfaFailCount(String userId) {
        if (userId == null) {
            return 0;
        }
        FailCountEntry entry = mfaFailCounts.get(userId);
        if (entry == null) {
            return 0;
        }
        if (clock.instant().isAfter(entry.expiresAt)) {
            mfaFailCounts.remove(userId);
            return 0;
        }
        return entry.count.get();
    }

    @Override
    public boolean isStale(String userId, long maxAgeMs) {
        if (userId == null) {
            return true;
        }
        AnalysisEntry entry = analysisStore.get(userId);
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
        if (userId == null) {
            return false;
        }
        Instant expiry = mfaPendingExpiry.get(userId);
        if (expiry == null) {
            return false;
        }
        if (Instant.now().isAfter(expiry)) {
            mfaPendingExpiry.remove(userId);
            return false;
        }
        return true;
    }

    @Override
    public void setBlockMfaPending(String userId) {
        if (userId != null) {
            mfaPendingExpiry.put(userId, Instant.now().plus(MFA_PENDING_TTL));
        }
    }

    @Override
    public boolean hasEscalateRetry(String userId) {
        if (userId == null) {
            return false;
        }
        Instant expiry = escalateRetries.get(userId);
        if (expiry != null && Instant.now().isBefore(expiry)) {
            return true;
        }
        escalateRetries.remove(userId);
        return false;
    }

    @Override
    public void setEscalateRetry(String userId, Duration ttl) {
        if (userId == null || ttl == null) {
            return;
        }
        escalateRetries.putIfAbsent(userId, Instant.now().plus(ttl));
    }

    @Override
    public void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        if (userId == null || action == null) {
            return;
        }

        AnalysisEntry existing = analysisStore.get(userId);
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

        ZeroTrustAction ztAction = action;
        if (ztAction.getDefaultTtl() != null) {
            entry.expiresAt = Instant.now().plus(ztAction.getDefaultTtl());
        }

        analysisStore.put(userId, entry);

        ActionEntry lastEntry = new ActionEntry();
        lastEntry.action = action.name();
        lastEntry.contextBindingHash = entry.contextBindingHash;
        lastEntry.expiresAt = Instant.now().plus(24, ChronoUnit.HOURS);
        lastVerifiedStore.put(userId, lastEntry);
    }

    @Override
    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction) {
        if (userId == null || newAction == null) {
            return;
        }

        AnalysisEntry existing = analysisStore.get(userId);
        AnalysisEntry entry = new AnalysisEntry();
        entry.action = newAction.name();
        entry.previousAction = existing != null ? existing.action : null;
        entry.updatedAt = Instant.now().toString();
        entry.contextBindingHash = null;

        if (existing != null) {
            entry.threatEvidence = existing.threatEvidence;
            entry.analysisDepth = existing.analysisDepth;
        }

        if (newAction.getDefaultTtl() != null) {
            entry.expiresAt = Instant.now().plus(newAction.getDefaultTtl());
        }

        analysisStore.put(userId, entry);

        ActionEntry lastEntry = new ActionEntry();
        lastEntry.action = newAction.name();
        lastEntry.contextBindingHash = null;
        lastEntry.expiresAt = Instant.now().plus(24, ChronoUnit.HOURS);
        lastVerifiedStore.put(userId, lastEntry);
    }

    @Override
    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash) {
        if (userId == null || newAction == null) {
            return;
        }

        AnalysisEntry existing = analysisStore.get(userId);
        AnalysisEntry entry = new AnalysisEntry();
        entry.action = newAction.name();
        entry.previousAction = existing != null ? existing.action : null;
        entry.updatedAt = Instant.now().toString();
        entry.contextBindingHash = contextBindingHash;

        if (existing != null) {
            entry.threatEvidence = existing.threatEvidence;
            entry.analysisDepth = existing.analysisDepth;
        }

        if (newAction.getDefaultTtl() != null) {
            entry.expiresAt = Instant.now().plus(newAction.getDefaultTtl());
        }

        analysisStore.put(userId, entry);

        ActionEntry lastEntry = new ActionEntry();
        lastEntry.action = newAction.name();
        lastEntry.contextBindingHash = contextBindingHash;
        lastEntry.expiresAt = Instant.now().plus(24, ChronoUnit.HOURS);
        lastVerifiedStore.put(userId, lastEntry);
    }

    @Override
    public void setBlockedFlag(String userId) {
        if (userId != null) {
            blockedUsers.add(userId);
        }
    }

    @Override
    public void removeBlockedFlag(String userId) {
        if (userId != null) {
            blockedUsers.remove(userId);
        }
    }

    @Override
    public void clearBlockMfaPending(String userId) {
        if (userId != null) {
            mfaPendingExpiry.remove(userId);
        }
    }

    @Override
    public long incrementBlockMfaFailCount(String userId) {
        if (userId == null) {
            return 0;
        }
        FailCountEntry entry = mfaFailCounts.compute(userId, (k, v) -> {
            if (v == null || clock.instant().isAfter(v.expiresAt)) {
                return new FailCountEntry(new AtomicLong(1), clock.instant().plus(failCountTtl));
            }
            v.count.incrementAndGet();
            return v;
        });
        return entry.count.get();
    }

    @Override
    public void removeAllUserData(String userId) {
        if (userId == null) {
            return;
        }
        analysisStore.remove(userId);
        lastVerifiedStore.remove(userId);
        blockedUsers.remove(userId);
        mfaFailCounts.remove(userId);
        mfaPendingExpiry.remove(userId);
        escalateRetries.remove(userId);
    }

    @Override
    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        if (userId == null || newAction == null) {
            return;
        }

        ReentrantLock lock = userLocks.computeIfAbsent(userId, k -> new ReentrantLock());
        lock.lock();
        try {
            blockedUsers.remove(userId);
            saveActionWithPrevious(userId, newAction);
        } finally {
            lock.unlock();
        }
    }

    private boolean isExpired(AnalysisEntry entry) {
        return entry.expiresAt != null && Instant.now().isAfter(entry.expiresAt);
    }

    private boolean isExpired(ActionEntry entry) {
        return entry.expiresAt != null && Instant.now().isAfter(entry.expiresAt);
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
        Instant expiresAt;
    }

    private boolean requiresFreshAnalysis(ZeroTrustAction action, String requestedContextHash, String storedContextHash) {
        return action != null
                && action != ZeroTrustAction.PENDING_ANALYSIS
                && action != ZeroTrustAction.BLOCK
                && requestedContextHash != null
                && storedContextHash != null
                && !storedContextHash.equals(requestedContextHash);
    }

    private static class ActionEntry {
        String action;
        String contextBindingHash;
        Instant expiresAt;
    }

    private static class FailCountEntry {
        final AtomicLong count;
        final Instant expiresAt;

        FailCountEntry(AtomicLong count, Instant expiresAt) {
            this.count = count;
            this.expiresAt = expiresAt;
        }
    }
}
