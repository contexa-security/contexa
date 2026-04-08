package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.LearningGovernanceSnapshotRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LearningGovernanceSnapshotRecordRepository extends JpaRepository<LearningGovernanceSnapshotRecord, Long> {

    Optional<LearningGovernanceSnapshotRecord> findByTenantIdAndArtifactType(String tenantId, String artifactType);
}