package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

/**
 * Immutable ledger entry for learning artifact release history.
 */
public record LearningArtifactReleaseLedgerEntry(
        String ledgerId,
        String tenantId,
        String artifactType,
        String artifactKey,
        String artifactVersion,
        LearningArtifactReleaseLedgerEventType eventType,
        LearningArtifactReleaseState releaseState,
        String policyState,
        String actor,
        String reason,
        String canaryOutcome,
        LearningArtifactReleaseState rollbackTargetState,
        boolean killSwitchActive,
        List<String> facts,
        LocalDateTime createdAt) {

    public LearningArtifactReleaseLedgerEntry {
        ledgerId = requireText(ledgerId, "ledgerId");
        tenantId = requireText(tenantId, "tenantId");
        artifactType = requireText(artifactType, "artifactType");
        artifactKey = requireText(artifactKey, "artifactKey");
        artifactVersion = normalizeNullable(artifactVersion);
        eventType = Objects.requireNonNull(eventType, "eventType is required");
        releaseState = Objects.requireNonNullElse(releaseState, LearningArtifactReleaseState.COLLECTING);
        policyState = normalizeNullable(policyState);
        actor = requireText(actor, "actor");
        reason = requireText(reason, "reason");
        canaryOutcome = normalizeNullable(canaryOutcome);
        rollbackTargetState = rollbackTargetState;
        facts = facts == null ? List.of() : List.copyOf(facts);
        createdAt = createdAt == null ? LocalDateTime.now() : createdAt;
    }

    private static String requireText(String value, String fieldName) {
        String normalized = normalizeNullable(value);
        if (normalized == null) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return normalized;
    }

    private static String normalizeNullable(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isEmpty() ? null : normalized;
    }
}
