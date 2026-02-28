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

/**
 * In-memory implementation of ZeroTrustActionRepository for standalone mode.
 * Uses ConcurrentHashMap instead of Redis Hash/String operations.
 */
@Slf4j
public class InMemoryZeroTrustActionRepository implements ZeroTrustActionRepository {

    private final ConcurrentHashMap<String, AnalysisEntry> analysisStore = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ActionEntry> lastVerifiedStore = new ConcurrentHashMap<>();
    private final Set<String> blockedUsers = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, AtomicLong> mfaFailCounts = new ConcurrentHashMap<>();
    private final Set<String> mfaPendingUsers = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Instant> escalateRetries = new ConcurrentHashMap<>();

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
        ZeroTrustAction action = getCurrentAction(userId);

        if (action == ZeroTrustAction.ALLOW && contextBindingHash != null) {
            AnalysisEntry entry = analysisStore.get(userId);
            if (entry != null && entry.contextBindingHash != null
                    && !entry.contextBindingHash.equals(contextBindingHash)) {
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
        }

        return action;
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
                entry.updatedAt
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
        AtomicLong count = mfaFailCounts.get(userId);
        return count != null ? count.get() : 0;
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
        return userId != null && mfaPendingUsers.contains(userId);
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
            Object riskScore = additionalFields.get("riskScore");
            if (riskScore instanceof Number num) {
                entry.riskScore = num.doubleValue();
            }
            Object confidence = additionalFields.get("confidence");
            if (confidence instanceof Number num) {
                entry.confidence = num.doubleValue();
            }
            Object threatEvidence = additionalFields.get("threatEvidence");
            if (threatEvidence != null) {
                entry.threatEvidence = threatEvidence.toString();
            }
            Object analysisDepth = additionalFields.get("analysisDepth");
            if (analysisDepth instanceof Number num) {
                entry.analysisDepth = num.intValue();
            }
            Object contextBindingHash = additionalFields.get("contextBindingHash");
            if (contextBindingHash != null) {
                entry.contextBindingHash = contextBindingHash.toString();
            }
        }

        ZeroTrustAction ztAction = action;
        if (ztAction.getDefaultTtl() != null) {
            entry.expiresAt = Instant.now().plus(ztAction.getDefaultTtl());
        }

        analysisStore.put(userId, entry);

        if (action != ZeroTrustAction.BLOCK) {
            ActionEntry lastEntry = new ActionEntry();
            lastEntry.action = action.name();
            lastEntry.expiresAt = Instant.now().plus(24, ChronoUnit.HOURS);
            lastVerifiedStore.put(userId, lastEntry);
        }
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
            entry.riskScore = existing.riskScore;
            entry.confidence = existing.confidence;
            entry.threatEvidence = existing.threatEvidence;
            entry.analysisDepth = existing.analysisDepth;
        }

        if (newAction.getDefaultTtl() != null) {
            entry.expiresAt = Instant.now().plus(newAction.getDefaultTtl());
        }

        analysisStore.put(userId, entry);
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
            entry.riskScore = existing.riskScore;
            entry.confidence = existing.confidence;
            entry.threatEvidence = existing.threatEvidence;
            entry.analysisDepth = existing.analysisDepth;
        }

        if (newAction.getDefaultTtl() != null) {
            entry.expiresAt = Instant.now().plus(newAction.getDefaultTtl());
        }

        analysisStore.put(userId, entry);
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
            mfaPendingUsers.remove(userId);
        }
    }

    @Override
    public long incrementBlockMfaFailCount(String userId) {
        if (userId == null) {
            return 0;
        }
        return mfaFailCounts
                .computeIfAbsent(userId, k -> new AtomicLong(0))
                .incrementAndGet();
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
        mfaPendingUsers.remove(userId);
        escalateRetries.remove(userId);
    }

    @Override
    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        if (userId == null || newAction == null) {
            return;
        }

        synchronized (userId.intern()) {
            blockedUsers.remove(userId);
            saveActionWithPrevious(userId, newAction);
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
        String contextBindingHash;
        Instant expiresAt;
    }

    private static class ActionEntry {
        String action;
        Instant expiresAt;
    }
}
