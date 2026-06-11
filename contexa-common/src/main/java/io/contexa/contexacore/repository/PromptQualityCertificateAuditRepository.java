package io.contexa.contexacore.repository;

import io.contexa.contexacore.saas.domain.entity.PromptQualityCertificateAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PromptQualityCertificateAuditRepository extends JpaRepository<PromptQualityCertificateAuditRecord, Long> {

    List<PromptQualityCertificateAuditRecord> findTop100ByOrderByRecordedAtDesc();

    List<PromptQualityCertificateAuditRecord> findTop100ByTenantIdOrderByRecordedAtDesc(String tenantId);

    List<PromptQualityCertificateAuditRecord> findTop100ByCertificateIdOrderByRecordedAtDesc(String certificateId);
}
