package io.contexa.contexacore.verification.evidence;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Storage port for sealed evidence packages.
 * Persistence technology and transaction ownership belong to downstream adapters.
 */
public interface SealedEvidencePackageRepository {

    SealedEvidencePackage save(SealedEvidencePackage evidencePackage);

    Optional<SealedEvidencePackage> findByPackageId(String packageId);

    Optional<SealedEvidencePackage> findByCorrelationId(String correlationId);

    Optional<SealedEvidencePackage> findByIdempotencyKey(String idempotencyKey);

    Page<SealedEvidencePackage> findByUserIdAndCapturedAtBetweenOrderByCapturedAtDesc(
            String userId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> findByTenantIdAndCapturedAtBetweenOrderByCapturedAtDesc(
            String tenantId, Instant from, Instant to, Pageable pageable);

    Page<SealedEvidencePackage> findByCapturedAtBetweenOrderByCapturedAtDesc(
            Instant from, Instant to, Pageable pageable);

    long countByTenantIdAndCapturedAtAfter(String tenantId, Instant after);

    /**
     * How many packages were captured at or after the time, whoever's they are: what the capture's daily limit counts.
     * This default counts through the page of a capture period; a store with a count of its own overrides it.
     */
    default long countCapturedSince(Instant since) {
        return findByCapturedAtBetweenOrderByCapturedAtDesc(since, Instant.now().plus(Duration.ofDays(1)),
                PageRequest.of(0, 1)).getTotalElements();
    }

    /**
     * The retention's delete: removes the packages whose expiry is before {@code now}. A package something still
     * stands on (a prompt version trial that decided it again, an administrator's evaluation of its decision) is left
     * past its expiry for as long as that is kept; a package without an expiry is never removed. One rule for every
     * package: what a prompt inspection found in it plays no part.
     *
     * @return how many packages were removed
     */
    long deleteByExpiresAtBefore(Instant now);
}