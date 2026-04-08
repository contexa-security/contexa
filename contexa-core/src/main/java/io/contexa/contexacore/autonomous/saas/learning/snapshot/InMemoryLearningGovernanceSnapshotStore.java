package io.contexa.contexacore.autonomous.saas.learning.snapshot;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryLearningGovernanceSnapshotStore implements LearningGovernanceSnapshotStore {

    private final ConcurrentMap<String, LearningGovernanceSnapshotEntry> entries = new ConcurrentHashMap<>();

    @Override
    public Optional<LearningGovernanceSnapshotEntry> find(String tenantId, String artifactType) {
        return Optional.ofNullable(entries.get(key(tenantId, artifactType)));
    }

    @Override
    public LearningGovernanceSnapshotEntry save(LearningGovernanceSnapshotEntry entry) {
        entries.put(key(entry.tenantId(), entry.artifactType()), entry);
        return entry;
    }

    private String key(String tenantId, String artifactType) {
        return tenantId.trim() + "|" + artifactType.trim();
    }
}