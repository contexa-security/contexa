package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.Scheduled;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The operator's re-inspection: one package at once, or a capture period by removing this inspector version's results
 * of it so that the automatic round inspects them again, its progress one count of the period (R1b-6); and the
 * automatic round's schedule and lock.
 */
class PromptInspectionReinspectionTest {

    private static final Instant NOW = Instant.parse("2026-10-12T06:00:00Z");
    private static final Instant T0 = Instant.parse("2026-10-12T05:00:00Z");

    private final InspectionStores.Packages packages = new InspectionStores.Packages()
            .add(InspectionStores.sealed("p1", T0.plusSeconds(10)))
            .add(InspectionStores.sealed("p2", T0.plusSeconds(20)))
            .add(InspectionStores.sealed("p3", T0.plusSeconds(30)));
    private final InspectionStores.Results results = new InspectionStores.Results(packages);
    private final PromptInspectionService service = new PromptInspectionService(
            new PromptInspector(PromptInspector.coreChecks(), new ObjectMapper()), packages, results,
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final PromptInspectionReinspection reinspection = new PromptInspectionReinspection(service, results, 40);

    @Test
    void onePackageIsReinspectedAtOnceAsTheOperators() {
        assertThat(reinspection.reinspect("p2")).isPresent();
        assertThat(results.findLatest("p2")).get().extracting(PromptInspectionRecord::trigger)
                .isEqualTo(PromptInspectionTrigger.OPERATOR);
        assertThat(reinspection.reinspect("missing")).isEmpty();
    }

    @Test
    void aPeriodIsInspectedAgainByTheRoundOnceItsResultsAreRemoved() {
        assertThat(service.inspectUninspected(3, 100)).isEqualTo(3);

        PromptInspectionReinspection.PeriodStatus requested = reinspection.request(T0, T0.plusSeconds(25));

        assertThat(requested.packages()).isEqualTo(2);
        assertThat(requested.uninspected()).isEqualTo(2);
        assertThat(results.findLatest("p1")).isEmpty();
        assertThat(results.findLatest("p2")).isEmpty();
        assertThat(results.findLatest("p3")).isPresent();

        assertThat(service.inspectUninspected(3, 100)).isEqualTo(2);
        assertThat(reinspection.status(T0, T0.plusSeconds(25)).uninspected()).isZero();
        assertThat(results.saves).extracting(record -> record.result().packageId())
                .containsExactly("p1", "p2", "p3", "p1", "p2");
    }

    @Test
    void theRemovalKeepsToTheShareTheRoundSamples() {
        reinspection.request(T0, T0.plusSeconds(25));

        assertThat(results.removedWithSample).isEqualTo(40);
    }

    @Test
    void aPeriodEndingBeforeItStartsIsRefused() {
        assertThatThrownBy(() -> reinspection.request(T0.plusSeconds(10), T0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theAutomaticRoundIsScheduledByItsIntervalAndRunsUnderOneLock() throws NoSuchMethodException {
        Method round = PromptInspectionScheduler.class.getMethod("inspectUninspected");

        assertThat(round.getAnnotation(Scheduled.class).fixedDelayString())
                .isEqualTo("${contexa.prompt-inspection.interval:PT30S}");
        assertThat(round.getAnnotation(SchedulerLock.class).name()).isEqualTo(PromptInspectionScheduler.LOCK_NAME);
    }
}
