package io.contexa.contexacore.verification.evidence;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface SealedEvidencePackageRepository extends JpaRepository<SealedEvidencePackage, Long> {

    Optional<SealedEvidencePackage> findByPackageId(String packageId);

    Optional<SealedEvidencePackage> findByCorrelationId(String correlationId);

    Page<SealedEvidencePackage> findByUserIdAndCapturedAtBetweenOrderByCapturedAtDesc(
            String userId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> findByTenantIdAndCapturedAtBetweenOrderByCapturedAtDesc(
            String tenantId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> findByCapturedAtBetweenOrderByCapturedAtDesc(
            Instant from, Instant to, Pageable pageable);

    long countByTenantIdAndCapturedAtAfter(String tenantId, Instant after);

    long deleteByExpiresAtBefore(Instant now);
}
