package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.Optional;

public class DefaultSealedEvidencePackageQueryService implements SealedEvidencePackageQueryService {

    private final SealedEvidencePackageLookupService lookupService;

    public DefaultSealedEvidencePackageQueryService(SealedEvidencePackageLookupService lookupService) {
        this.lookupService = lookupService;
    }

    @Override
    public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
        return lookupService.findByPackageId(packageId);
    }

    @Override
    public Page<SealedEvidencePackage> searchRecent(Instant from, Instant to, Pageable pageable) {
        return lookupService.searchRecent(from, to, pageable);
    }

    @Override
    public Page<SealedEvidencePackage> searchByTenantId(String tenantId, Instant from, Instant to, Pageable pageable) {
        return lookupService.searchByTenantId(tenantId, from, to, pageable);
    }

    @Override
    public Page<SealedEvidencePackage> searchByUserId(String userId, Instant from, Instant to, Pageable pageable) {
        return lookupService.searchByUserId(userId, from, to, pageable);
    }

    @Override
    public boolean verifyIntegrity(SealedEvidencePackage evidencePackage) {
        return lookupService.verifyIntegrity(evidencePackage);
    }
}
