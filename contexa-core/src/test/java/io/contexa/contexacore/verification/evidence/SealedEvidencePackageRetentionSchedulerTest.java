package io.contexa.contexacore.verification.evidence;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.Scheduled;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class SealedEvidencePackageRetentionSchedulerTest {

    @Test
    void cleanupDeletesPackagesWhoseRetentionHasExpired() {
        SealedEvidencePackageRepository repository = mock(SealedEvidencePackageRepository.class);
        Instant now = Instant.parse("2026-10-02T03:30:00Z");
        SealedEvidencePackageRetentionScheduler scheduler =
                new SealedEvidencePackageRetentionScheduler(repository, Clock.fixed(now, ZoneOffset.UTC));

        scheduler.deleteExpiredPackages();

        verify(repository).deleteByExpiresAtBefore(now);
    }

    @Test
    void cleanupIsScheduledAndGuardedByAClusterLock() throws NoSuchMethodException {
        Method method = SealedEvidencePackageRetentionScheduler.class.getMethod("deleteExpiredPackages");

        assertThat(method.getAnnotation(Scheduled.class).cron())
                .isEqualTo("${contexa.pqa.oss.sealed-evidence.retention.cleanup-cron:0 30 3 * * *}");
        SchedulerLock lock = method.getAnnotation(SchedulerLock.class);
        assertThat(lock.name()).isEqualTo(SealedEvidencePackageRetentionScheduler.LOCK_NAME);
        assertThat(lock.lockAtMostFor()).isEqualTo("PT30M");
    }
}
