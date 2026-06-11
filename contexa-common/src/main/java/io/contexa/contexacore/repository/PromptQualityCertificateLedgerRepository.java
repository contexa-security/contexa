package io.contexa.contexacore.repository;

import io.contexa.contexacore.saas.domain.entity.PromptQualityCertificateLedgerRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PromptQualityCertificateLedgerRepository extends JpaRepository<PromptQualityCertificateLedgerRecord, Long> {

    Optional<PromptQualityCertificateLedgerRecord> findFirstByResourceKeyOrderByRecordedAtDesc(String resourceKey);

    Optional<PromptQualityCertificateLedgerRecord> findFirstByScopeHashOrderByRecordedAtDesc(String scopeHash);

    List<PromptQualityCertificateLedgerRecord> findByScopeHashInOrderByRecordedAtDesc(Collection<String> scopeHashes);

    Optional<PromptQualityCertificateLedgerRecord> findFirstByCertificateIdOrderByRecordedAtDesc(String certificateId);

    Optional<PromptQualityCertificateLedgerRecord> findFirstBySealedEvidencePackageIdOrderByRecordedAtDesc(String sealedEvidencePackageId);

    List<PromptQualityCertificateLedgerRecord> findTop20ByResourceIdOrderByRecordedAtDesc(String resourceId);

    List<PromptQualityCertificateLedgerRecord> findTop20ByTenantIdAndResourceIdAndHttpMethodOrderByRecordedAtDesc(
            String tenantId,
            String resourceId,
            String httpMethod
    );

    List<PromptQualityCertificateLedgerRecord> findByTenantIdAndPromptContractVersionOrderByRecordedAtDesc(
            String tenantId,
            String promptContractVersion
    );

    List<PromptQualityCertificateLedgerRecord> findByTenantIdAndModelProfileOrderByRecordedAtDesc(
            String tenantId,
            String modelProfile
    );

    List<PromptQualityCertificateLedgerRecord> findByTenantIdAndVerifierVersionOrderByRecordedAtDesc(
            String tenantId,
            String verifierVersion
    );

    List<PromptQualityCertificateLedgerRecord> findByTenantIdOrderByRecordedAtDesc(String tenantId);

    List<PromptQualityCertificateLedgerRecord> findTop100ByOrderByRecordedAtDesc();
}
