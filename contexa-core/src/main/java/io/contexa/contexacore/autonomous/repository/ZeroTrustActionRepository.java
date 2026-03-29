package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.time.Duration;
import java.util.Map;

/**
 * Abstraction for Zero Trust action storage and retrieval.
 * Implementations: ZeroTrustActionRedisRepository (distributed), InMemoryZeroTrustActionRepository (standalone).
 */
public interface ZeroTrustActionRepository {

    // --- Query ---

    ZeroTrustAction getCurrentAction(String userId);

    ZeroTrustAction getCurrentAction(String userId, String contextBindingHash);

    ZeroTrustAnalysisData getAnalysisData(String userId);

    ZeroTrustAction getActionFromHash(String userId);

    ZeroTrustAction getPreviousActionFromHash(String userId);

    ZeroTrustAction getLastVerifiedAction(String userId);

    long getBlockMfaFailCount(String userId);

    boolean isStale(String userId, long maxAgeMs);

    // --- Escalate/Block MFA state ---

    boolean isBlockMfaPending(String userId);

    void setBlockMfaPending(String userId);

    boolean hasEscalateRetry(String userId);

    void setEscalateRetry(String userId, Duration ttl);

    // --- Save ---

    void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields);

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction);

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash);

    // --- Blocking state ---

    void setBlockedFlag(String userId);

    void removeBlockedFlag(String userId);

    void clearBlockMfaPending(String userId);

    long incrementBlockMfaFailCount(String userId);

    void removeAllUserData(String userId);

    // --- Transaction ---

    void approveOverrideAtomically(String userId, ZeroTrustAction newAction);

    // --- Analysis data record ---

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
        public static ZeroTrustAnalysisData pending() {
            return new ZeroTrustAnalysisData(
                    ZeroTrustAction.PENDING_ANALYSIS.name(),
                    null,  null, null, null, null, null, null, null, null, null
            );
        }
    }
}
