package io.contexa.contexacore.repository;

import io.contexa.contexacore.saas.domain.entity.PromptQualityIssueCaseRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PromptQualityIssueCaseRepository extends JpaRepository<PromptQualityIssueCaseRecord, Long> {

    Optional<PromptQualityIssueCaseRecord> findFirstByCaseIdOrderByUpdatedAtDesc(String caseId);

    Optional<PromptQualityIssueCaseRecord> findFirstByTenantIdAndScopeHashAndStateOrderByUpdatedAtDesc(
            String tenantId,
            String scopeHash,
            String state
    );

    List<PromptQualityIssueCaseRecord> findTop100ByOrderByUpdatedAtDesc();

    List<PromptQualityIssueCaseRecord> findTop100ByTenantIdOrderByUpdatedAtDesc(String tenantId);
}
