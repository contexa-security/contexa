package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.LearningArtifactRegistryRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface LearningArtifactRegistryRecordRepository extends JpaRepository<LearningArtifactRegistryRecord, Long> {

    Optional<LearningArtifactRegistryRecord> findFirstByTenantIdAndArtifactTypeAndArtifactKeyOrderByUpdatedAtDesc(
            String tenantId,
            String artifactType,
            String artifactKey);

    List<LearningArtifactRegistryRecord> findByArtifactTypeAndArtifactKeyOrderByUpdatedAtDesc(
            String artifactType,
            String artifactKey);

    List<LearningArtifactRegistryRecord> findByTenantIdOrderByUpdatedAtDesc(String tenantId);
}