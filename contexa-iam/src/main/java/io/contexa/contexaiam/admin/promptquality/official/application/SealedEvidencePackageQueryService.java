package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.Optional;

public interface SealedEvidencePackageQueryService {

    Optional<SealedEvidencePackage> findByPackageId(String packageId);

    default Optional<SealedEvidencePackage> findLightweightByPackageId(String packageId) {
        return findByPackageId(packageId);
    }

    Page<SealedEvidencePackage> searchRecent(Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> searchByTenantId(String tenantId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> searchByUserId(String userId, Instant from, Instant to, Pageable pageable);

    boolean verifyIntegrity(SealedEvidencePackage evidencePackage);
}
