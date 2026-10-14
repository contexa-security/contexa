package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** R4-S5: the short retention of the packages whose latest inspection found nothing wrong. */
class PromptInspectionCleanPackageRetentionSchedulerTest {

    private static final Instant NOW = Instant.parse("2026-11-20T03:30:00Z");

    private final InspectionStores.Packages packages = new InspectionStores.Packages();
    private final InspectionStores.Results results = new InspectionStores.Results(packages);

    @Test
    void aPackageWhoseLatestInspectionFoundNothingWrongGoesAfterTheCleanPeriod() {
        inspected("clean-31-days", NOW.minus(Duration.ofDays(31)), PromptInspectionVerdict.PASS);
        inspected("not-applicable-31-days", NOW.minus(Duration.ofDays(31)), PromptInspectionVerdict.NOT_APPLICABLE);
        inspected("clean-29-days", NOW.minus(Duration.ofDays(29)), PromptInspectionVerdict.PASS);
        inspected("failed-31-days", NOW.minus(Duration.ofDays(31)), PromptInspectionVerdict.FAIL);
        packages.add(InspectionStores.sealed("uninspected-31-days", NOW.minus(Duration.ofDays(31))));

        retention(Duration.ofDays(30)).removeCleanPackages();

        assertThat(packages.oldestFirst()).extracting(SealedEvidencePackage::getPackageId)
                .containsExactlyInAnyOrder("clean-29-days", "failed-31-days", "uninspected-31-days");
        assertThat(results.findAll("clean-31-days")).isEmpty();
    }

    @Test
    void moreCleanPackagesThanOneBatchAreAllRemovedInOneRun() {
        int count = PromptInspectionCleanPackageRetentionScheduler.BATCH_SIZE * 2 + 7;
        for (int index = 0; index < count; index++) {
            inspected("clean-" + index, NOW.minus(Duration.ofDays(40)).plusSeconds(index), PromptInspectionVerdict.PASS);
        }

        retention(Duration.ofDays(30)).removeCleanPackages();

        assertThat(packages.oldestFirst()).isEmpty();
    }

    @Test
    void theCleanPeriodMustBePositive() {
        assertThatThrownBy(() -> new PromptInspectionCleanPackageRetentionScheduler(results, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PromptInspectionCleanPackageRetentionScheduler(results, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private PromptInspectionCleanPackageRetentionScheduler retention(Duration cleanPeriod) {
        return new PromptInspectionCleanPackageRetentionScheduler(results, cleanPeriod,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void inspected(String packageId, Instant capturedAt, PromptInspectionVerdict verdict) {
        packages.add(InspectionStores.sealed(packageId, capturedAt));
        results.save(new PromptInspectionResult(packageId, "prompt-inspector/1", null, null, verdict, List.of(),
                null), PromptInspectionTrigger.AUTO, capturedAt.plusSeconds(60));
    }
}
