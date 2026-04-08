package io.contexa.contexacore.autonomous.saas.learning.snapshot;

import java.util.Optional;

public interface LearningGovernanceSnapshotStore {

    Optional<LearningGovernanceSnapshotEntry> find(String tenantId, String artifactType);

    LearningGovernanceSnapshotEntry save(LearningGovernanceSnapshotEntry entry);
}