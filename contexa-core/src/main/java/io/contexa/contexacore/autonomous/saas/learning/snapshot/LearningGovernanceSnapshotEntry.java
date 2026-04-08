package io.contexa.contexacore.autonomous.saas.learning.snapshot;

import java.time.LocalDateTime;

/**
 * Canonical stored governance snapshot payload for non-runtime learning artifacts.
 */
public record LearningGovernanceSnapshotEntry(
        String tenantId,
        String artifactType,
        String snapshotJson,
        LocalDateTime generatedAt,
        LocalDateTime refreshedAt) {
}