package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.LearningArtifactReleaseLedgerRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface LearningArtifactReleaseLedgerRecordRepository extends JpaRepository<LearningArtifactReleaseLedgerRecord, Long> {

    Optional<LearningArtifactReleaseLedgerRecord> findFirstByTenantIdAndArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
            String tenantId,
            String artifactType,
            String artifactKey);

    List<LearningArtifactReleaseLedgerRecord> findByTenantIdAndArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
            String tenantId,
            String artifactType,
            String artifactKey,
            Pageable pageable);

    List<LearningArtifactReleaseLedgerRecord> findByArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
            String artifactType,
            String artifactKey,
            Pageable pageable);
}