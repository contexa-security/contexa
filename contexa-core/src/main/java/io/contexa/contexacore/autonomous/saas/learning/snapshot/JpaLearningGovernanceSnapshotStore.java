package io.contexa.contexacore.autonomous.saas.learning.snapshot;

import io.contexa.contexacore.domain.entity.LearningGovernanceSnapshotRecord;
import io.contexa.contexacore.repository.LearningGovernanceSnapshotRecordRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public class JpaLearningGovernanceSnapshotStore implements LearningGovernanceSnapshotStore {

    private final LearningGovernanceSnapshotRecordRepository repository;

    public JpaLearningGovernanceSnapshotStore(LearningGovernanceSnapshotRecordRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<LearningGovernanceSnapshotEntry> find(String tenantId, String artifactType) {
        return repository.findByTenantIdAndArtifactType(tenantId.trim(), artifactType.trim())
                .map(this::toEntry);
    }

    @Override
    public LearningGovernanceSnapshotEntry save(LearningGovernanceSnapshotEntry entry) {
        LearningGovernanceSnapshotRecord current = repository.findByTenantIdAndArtifactType(
                        entry.tenantId().trim(),
                        entry.artifactType().trim())
                .orElseGet(LearningGovernanceSnapshotRecord::new);
        current.setTenantId(entry.tenantId().trim());
        current.setArtifactType(entry.artifactType().trim());
        current.setGeneratedAt(entry.generatedAt());
        current.setSnapshotJson(entry.snapshotJson());
        LearningGovernanceSnapshotRecord saved = repository.save(current);
        return toEntry(saved);
    }

    private LearningGovernanceSnapshotEntry toEntry(LearningGovernanceSnapshotRecord record) {
        LocalDateTime refreshedAt = record.getUpdatedAt() != null ? record.getUpdatedAt() : record.getCreatedAt();
        return new LearningGovernanceSnapshotEntry(
                record.getTenantId(),
                record.getArtifactType(),
                record.getSnapshotJson(),
                record.getGeneratedAt(),
                refreshedAt);
    }
}