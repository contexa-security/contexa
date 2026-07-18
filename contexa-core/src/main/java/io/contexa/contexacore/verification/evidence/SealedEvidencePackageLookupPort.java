package io.contexa.contexacore.verification.evidence;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.Optional;

/**
 * Sealed-evidence lookup contract shared by OSS storage and Enterprise adapters.
 */
public interface SealedEvidencePackageLookupPort {

    Optional<SealedEvidencePackage> findByPackageId(String packageId);

    Optional<SealedEvidencePackage> findByCorrelationId(String correlationId);

    Page<SealedEvidencePackage> searchByUserId(
            String userId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> searchByTenantId(
            String tenantId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> searchRecent(Instant from, Instant to, Pageable pageable);

    boolean verifyIntegrity(SealedEvidencePackage evidencePackage);

    Optional<SealedEvidencePackage> findWithIntegrityCheck(String packageId);
}