package io.contexa.contexacore.verification.evidence;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.Optional;

/**
 * Provides query methods for sealed evidence packages with integrity verification.
 */
@RequiredArgsConstructor
public class SealedEvidencePackageLookupService implements SealedEvidencePackageLookupPort {

    private final SealedEvidencePackageRepository repository;
    private final SealedEvidencePackageIntegrity integrity;

    public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
        return repository.findByPackageId(packageId);
    }

    public Optional<SealedEvidencePackage> findByCorrelationId(String correlationId) {
        return repository.findByCorrelationId(correlationId);
    }

    public Page<SealedEvidencePackage> searchByUserId(String userId, Instant from, Instant to, Pageable pageable) {
        return repository.findByUserIdAndCapturedAtBetweenOrderByCapturedAtDesc(userId, from, to, pageable);
    }

    public Page<SealedEvidencePackage> searchByTenantId(String tenantId, Instant from, Instant to, Pageable pageable) {
        return repository.findByTenantIdAndCapturedAtBetweenOrderByCapturedAtDesc(tenantId, from, to, pageable);
    }

    public Page<SealedEvidencePackage> searchRecent(Instant from, Instant to, Pageable pageable) {
        return repository.findByCapturedAtBetweenOrderByCapturedAtDesc(from, to, pageable);
    }

    public boolean verifyIntegrity(SealedEvidencePackage pkg) {
        return integrity.verify(pkg);
    }

    public Optional<SealedEvidencePackage> findWithIntegrityCheck(String packageId) {
        return repository.findByPackageId(packageId)
                .map(pkg -> {
                    if (!integrity.verify(pkg)) {
                        pkg.setSealed(false);
                    }
                    return pkg;
                });
    }
}
