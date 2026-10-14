package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The inspection service: a round inspects the oldest packages without a result of this inspector version, up to the
 * batch, and stores each result; an operator inspection of one package stores it as the operator's.
 */
class PromptInspectionServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-12T06:00:00Z");
    private static final Instant T0 = Instant.parse("2026-10-12T05:00:00Z");

    private final InspectionStores.Packages packages = new InspectionStores.Packages()
            .add(InspectionStores.sealed("p3", T0.plusSeconds(30)))
            .add(InspectionStores.sealed("p1", T0.plusSeconds(10)))
            .add(InspectionStores.sealed("p2", T0.plusSeconds(20)));
    private final InspectionStores.Results results = new InspectionStores.Results(packages);
    private final PromptInspectionService service = new PromptInspectionService(
            new PromptInspector(PromptInspector.coreChecks(), new ObjectMapper()), packages, results,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aRoundInspectsTheOldestUninspectedPackagesUpToTheBatchAndStoresThemAsAutomatic() {
        assertThat(service.inspectUninspected(2, 100)).isEqualTo(2);

        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p1", "p2");
        assertThat(results.saves).allMatch(record -> record.trigger() == PromptInspectionTrigger.AUTO
                && NOW.equals(record.inspectedAt())
                && PromptInspector.INSPECTOR_VERSION.equals(record.result().inspectorVersion()));

        assertThat(service.inspectUninspected(2, 100)).isEqualTo(1);
        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p1", "p2", "p3");
        assertThat(service.inspectUninspected(2, 100)).isZero();
    }

    @Test
    void aPackageRemovedBeforeItIsReadIsLeftOutAndTheOthersAreInspected() {
        PromptInspectionResultStore removing = new PromptInspectionResultStore() {
            @Override
            public List<String> findUninspectedPackageIds(String inspectorVersion, int limit, int samplePercent) {
                List<String> ids = results.findUninspectedPackageIds(inspectorVersion, limit, samplePercent);
                packages.remove("p1");
                return ids;
            }

            @Override
            public void save(PromptInspectionResult result, PromptInspectionTrigger trigger, Instant inspectedAt) {
                results.save(result, trigger, inspectedAt);
            }

            @Override
            public List<PromptInspectionRecord> findAll(String packageId) {
                return results.findAll(packageId);
            }

            @Override
            public int removeResults(String inspectorVersion, Instant from, Instant to, int samplePercent) {
                return results.removeResults(inspectorVersion, from, to, samplePercent);
            }

            @Override
            public int removeCleanPackagesCapturedBefore(Instant before, int limit) {
                return results.removeCleanPackagesCapturedBefore(before, limit);
            }

            @Override
            public PeriodCount countPeriod(String inspectorVersion, Instant from, Instant to, int samplePercent) {
                return results.countPeriod(inspectorVersion, from, to, samplePercent);
            }
        };
        PromptInspectionService racing = new PromptInspectionService(
                new PromptInspector(PromptInspector.coreChecks(), new ObjectMapper()), packages, removing,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(racing.inspectUninspected(3, 100)).isEqualTo(2);
        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p2", "p3");
    }

    @Test
    void aResultThatCannotBeStoredLeavesThePackageForTheNextRoundAndTheOthersStored() {
        results.failing.add("p2");

        assertThat(service.inspectUninspected(3, 100)).isEqualTo(2);
        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p1", "p3");

        results.failing.clear();
        assertThat(service.inspectUninspected(3, 100)).isEqualTo(1);
        assertThat(results.findLatest("p2")).isPresent();
    }

    /** R1b-5: a source a check reads that is unavailable now stops the round; the package is tried again later. */
    @Test
    void aRoundStopsWhereASourceIsUnavailableNowAndStoresNothingForThatPackage() {
        AtomicBoolean down = new AtomicBoolean(true);
        PromptInspectionService registryDown = new PromptInspectionService(
                new PromptInspector(List.of(unavailableFor("p2", down)), new ObjectMapper()), packages, results,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(registryDown.inspectUninspected(3, 100)).isEqualTo(1);
        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p1");

        down.set(false);
        assertThat(registryDown.inspectUninspected(3, 100)).isEqualTo(2);
        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p1", "p2", "p3");
    }

    /** R1b-5: a package that keeps failing is tried after the others, so it never holds the front of a round. */
    @Test
    void aPackageThatKeepsFailingIsTriedAfterTheOthersAndDoesNotHoldTheRoundsFront() {
        results.failing.add("p1");

        assertThat(service.inspectUninspected(1, 100)).isZero();
        assertThat(service.inspectUninspected(1, 100)).isEqualTo(1);
        assertThat(service.inspectUninspected(1, 100)).isEqualTo(1);
        assertThat(results.saves).extracting(record -> record.result().packageId()).containsExactly("p2", "p3");

        assertThat(service.inspectUninspected(1, 100)).isZero();
        results.failing.clear();
        assertThat(service.inspectUninspected(1, 100)).isEqualTo(1);
        assertThat(results.findLatest("p1")).isPresent();
    }

    @Test
    void anOperatorInspectionOfOnePackageIsStoredAsTheOperatorsAndUnknownPackagesAreNone() {
        assertThat(service.inspect("p2", PromptInspectionTrigger.OPERATOR)).get()
                .extracting(PromptInspectionResult::packageId).isEqualTo("p2");
        assertThat(results.findLatest("p2")).get()
                .extracting(PromptInspectionRecord::trigger).isEqualTo(PromptInspectionTrigger.OPERATOR);

        assertThat(service.inspect("missing", PromptInspectionTrigger.OPERATOR)).isEmpty();
    }

    @Test
    void theRoundRunsOnTheThreadThatCallsIt() {
        AtomicReference<String> storedOn = new AtomicReference<>();
        PromptInspectionResultStore recording = new PromptInspectionResultStore() {
            @Override
            public List<String> findUninspectedPackageIds(String inspectorVersion, int limit, int samplePercent) {
                return results.findUninspectedPackageIds(inspectorVersion, limit, samplePercent);
            }

            @Override
            public void save(PromptInspectionResult result, PromptInspectionTrigger trigger, Instant inspectedAt) {
                storedOn.set(Thread.currentThread().getName());
                results.save(result, trigger, inspectedAt);
            }

            @Override
            public List<PromptInspectionRecord> findAll(String packageId) {
                return results.findAll(packageId);
            }

            @Override
            public int removeResults(String inspectorVersion, Instant from, Instant to, int samplePercent) {
                return results.removeResults(inspectorVersion, from, to, samplePercent);
            }

            @Override
            public int removeCleanPackagesCapturedBefore(Instant before, int limit) {
                return results.removeCleanPackagesCapturedBefore(before, limit);
            }

            @Override
            public PeriodCount countPeriod(String inspectorVersion, Instant from, Instant to, int samplePercent) {
                return results.countPeriod(inspectorVersion, from, to, samplePercent);
            }
        };
        new PromptInspectionScheduler(new PromptInspectionService(
                new PromptInspector(PromptInspector.coreChecks(), new ObjectMapper()), packages, recording,
                Clock.fixed(NOW, ZoneOffset.UTC)), 50, 100).inspectUninspected();

        assertThat(storedOn.get()).isEqualTo(Thread.currentThread().getName());
        assertThat(results.saves).hasSize(3);
    }

    private static PromptInspectionCheck unavailableFor(String packageId, AtomicBoolean down) {
        return new PromptInspectionCheck() {
            @Override
            public String code() {
                return "REGISTRY_READ";
            }

            @Override
            public boolean dictionaryPromptOnly() {
                return false;
            }

            @Override
            public void inspect(PromptInspectionTally tally) {
                if (down.get() && packageId.equals(tally.subject().evidencePackage().getPackageId())) {
                    throw new PromptInspectionUnavailableException("the release registry is not available", null);
                }
                tally.matched();
            }
        };
    }
}
