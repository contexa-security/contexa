package io.contexa.contexacore.autonomous.saas.learning.registry;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerEventType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

/**
 * Canonical latest-state view for a tenant-scoped learning artifact.
 */
public record LearningArtifactRegistryEntry(
        String tenantId,
        String artifactType,
        String artifactKey,
        String artifactVersion,
        LearningArtifactReleaseState releaseState,
        String policyState,
        LearningArtifactReleaseLedgerEventType latestEventType,
        boolean killSwitchActive,
        boolean runtimeEligible,
        boolean runtimeSuppressed,
        String actor,
        String reason,
        String canaryOutcome,
        LearningArtifactReleaseState rollbackTargetState,
        List<String> facts,
        LocalDateTime firstRegisteredAt,
        LocalDateTime lastLedgerAt,
        LocalDateTime updatedAt) {

    public LearningArtifactRegistryEntry {
        tenantId = requireText(tenantId, "tenantId");
        artifactType = requireText(artifactType, "artifactType");
        artifactKey = requireText(artifactKey, "artifactKey");
        artifactVersion = normalizeNullable(artifactVersion);
        releaseState = Objects.requireNonNullElse(releaseState, LearningArtifactReleaseState.COLLECTING);
        policyState = normalizeNullable(policyState);
        latestEventType = Objects.requireNonNull(latestEventType, "latestEventType is required");
        actor = requireText(actor, "actor");
        reason = requireText(reason, "reason");
        canaryOutcome = normalizeNullable(canaryOutcome);
        facts = facts == null ? List.of() : List.copyOf(facts);
        firstRegisteredAt = firstRegisteredAt == null ? LocalDateTime.now() : firstRegisteredAt;
        lastLedgerAt = lastLedgerAt == null ? firstRegisteredAt : lastLedgerAt;
        updatedAt = updatedAt == null ? lastLedgerAt : updatedAt;
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