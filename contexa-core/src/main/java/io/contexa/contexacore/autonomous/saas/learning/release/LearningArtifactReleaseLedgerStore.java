package io.contexa.contexacore.autonomous.saas.learning.release;

import java.util.List;
import java.util.Optional;

/**
 * Storage abstraction for learning artifact release ledger entries.
 */
public interface LearningArtifactReleaseLedgerStore {

    LearningArtifactReleaseLedgerEntry save(LearningArtifactReleaseLedgerEntry entry);

    Optional<LearningArtifactReleaseLedgerEntry> findLatest(String tenantId, String artifactType, String artifactKey);

    List<LearningArtifactReleaseLedgerEntry> findRecent(String tenantId, String artifactType, String artifactKey, int limit);

    List<LearningArtifactReleaseLedgerEntry> findLatestByArtifact(String artifactType, String artifactKey);

    List<LearningArtifactReleaseLedgerEntry> findRecentByArtifact(String artifactType, String artifactKey, int limit);
}