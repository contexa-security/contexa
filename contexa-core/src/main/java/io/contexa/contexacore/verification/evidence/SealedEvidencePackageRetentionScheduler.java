package io.contexa.contexacore.verification.evidence;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.util.Objects;

/**
 * Enforces the sealed evidence retention contract by deleting packages whose expiresAt has passed.
 *
 * The schedule is guarded by a ShedLock lock so that only one node runs the cleanup at a time when
 * scheduler locking is enabled. Packages without expiresAt are never deleted.
 */
public class SealedEvidencePackageRetentionScheduler {

    public static final String LOCK_NAME = "sealedEvidencePackageRetentionCleanup";

    private final SealedEvidencePackageRepository repository;
    private final Clock clock;

    public SealedEvidencePackageRetentionScheduler(SealedEvidencePackageRepository repository) {
        this(repository, Clock.systemUTC());
    }

    public SealedEvidencePackageRetentionScheduler(SealedEvidencePackageRepository repository, Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Scheduled(cron = "${contexa.pqa.oss.sealed-evidence.retention.cleanup-cron:0 30 3 * * *}")
    @SchedulerLock(name = LOCK_NAME, lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    public void deleteExpiredPackages() {
        repository.deleteByExpiresAtBefore(clock.instant());
    }
}
