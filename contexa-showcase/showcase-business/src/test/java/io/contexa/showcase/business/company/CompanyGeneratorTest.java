package io.contexa.showcase.business.company;

import io.contexa.showcase.business.company.CompanyDataset.Assignment;
import io.contexa.showcase.business.company.CompanyDataset.Employee;
import io.contexa.showcase.business.company.CompanyDataset.Device;
import io.contexa.showcase.business.company.CompanyDataset.ScriptedActivity;
import io.contexa.showcase.business.company.CompanyDataset.TravelPlan;
import io.contexa.showcase.business.context.Networks;
import org.junit.jupiter.api.Test;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * The virtual company is a pure function of seed and anchor date (deck p.26 principle 4) and has the shape the
 * scenes rely on (ADR-19, ADR-23).
 */
class CompanyGeneratorTest {

    private static final LocalDate ANCHOR = LocalDate.of(2026, 9, 30);

    private final CompanyGenerator generator = new CompanyGenerator();

    @Test
    void theSameSeedAndAnchorGiveTheSameCompany() {
        CompanyDataset first = generator.generate(20261005L, ANCHOR);
        CompanyDataset second = generator.generate(20261005L, ANCHOR);

        assertThat(second).isEqualTo(first);
        assertThat(second.fingerprint()).isEqualTo(first.fingerprint()).hasSize(64);
        assertThat(generator.generate(20261006L, ANCHOR).fingerprint()).isNotEqualTo(first.fingerprint());
        assertThat(generator.generate(20261005L, ANCHOR.minusWeeks(1)).fingerprint()).isNotEqualTo(first.fingerprint());
    }

    @Test
    void headCountsFollowTheDeck() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);
        Map<String, Long> byRole = company.employees().stream()
                .collect(Collectors.groupingBy(Employee::roleKey, Collectors.counting()));

        assertThat(company.employees()).hasSize(120);
        assertThat(byRole).containsExactlyInAnyOrderEntriesOf(Map.of(
                "ENGINEER", 60L, "SALES", 20L, "PM", 12L, "PARTNER", 12L, "FINANCE", 10L, "ADMIN", 6L));
        assertThat(company.employees()).extracting(Employee::employeeKey)
                .contains(CompanyBlueprint.ADMIN_A, CompanyBlueprint.ENGINEER_K)
                .doesNotHaveDuplicates();
        assertThat(company.employees()).extracting(Employee::email).doesNotHaveDuplicates();
    }

    @Test
    void theRepresentativeExportTargetIsLargeAndForeignToAdministratorA() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);

        long targetDocuments = company.documents().stream()
                .filter(d -> d.projectKey().equals(CompanyBlueprint.A3_TARGET)).count();
        assertThat(targetDocuments).as("the 5,000+ export condition needs more than 5,000 documents").isGreaterThan(5_000);
        assertThat(company.assignments())
                .noneMatch(a -> a.employeeKey().equals(CompanyBlueprint.ADMIN_A)
                        && a.projectKey().equals(CompanyBlueprint.A3_TARGET));
        assertThat(company.accessHistory())
                .noneMatch(a -> a.employeeKey().equals(CompanyBlueprint.ADMIN_A)
                        && a.projectKey().equals(CompanyBlueprint.A3_TARGET));
        assertThat(company.assignments()).extracting(Assignment::employeeKey, Assignment::projectKey)
                .contains(tuple(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.K_PROJECT),
                        tuple(CompanyBlueprint.ADMIN_A, CompanyBlueprint.PLM_OPERATIONS));
    }

    /**
     * Admin A learns on the five workdays of the previous week (25 requests); engineer K (approval Q-43) and the two
     * baseline variants (W2-7) on the ten workdays of the previous two weeks (50 requests).
     */
    @Test
    void protagonistsHaveTheirLearnedRequestsOnTheWorkdaysBeforeTheAnchor() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);
        assertThat(ANCHOR.getDayOfWeek()).isEqualTo(DayOfWeek.WEDNESDAY);
        assertThat(company.scriptedActivities()).extracting(ScriptedActivity::employeeKey).containsOnly(
                CompanyBlueprint.ADMIN_A, CompanyBlueprint.ENGINEER_K, CompanyBlueprint.ADMIN_NIGHT,
                CompanyBlueprint.ENGINEER_FIELD);

        for (String protagonist : Set.of(CompanyBlueprint.ADMIN_A, CompanyBlueprint.ENGINEER_K,
                CompanyBlueprint.ADMIN_NIGHT, CompanyBlueprint.ENGINEER_FIELD)) {
            int learnedDays = CompanyBlueprint.ADMIN_A.equals(protagonist) ? 7 : 14;
            assertThat(CompanyGenerator.learnedDays(protagonist)).as(protagonist).isEqualTo(learnedDays);
            var activities = company.scriptedActivities().stream()
                    .filter(a -> a.employeeKey().equals(protagonist)).toList();
            Set<LocalDate> days = activities.stream()
                    .map(a -> LocalDate.ofInstant(a.observedAt(), ZoneOffset.UTC))
                    .collect(Collectors.toSet());
            assertThat(activities).as(protagonist).hasSize(learnedDays / 7 * 25);
            assertThat(days).as(protagonist).hasSize(learnedDays / 7 * 5).allSatisfy(day -> {
                assertThat(day).isBefore(ANCHOR).isAfterOrEqualTo(ANCHOR.minusDays(learnedDays));
                assertThat(CompanyCalendar.isWorkday(day)).isTrue();
            });
            assertThat(days).as("the run's weekday is a usual workday").anyMatch(day -> day.getDayOfWeek() == ANCHOR.getDayOfWeek());
            Instant earliestRunTime = CompanyCalendar.at(ANCHOR, TimeSlot.DAWN);
            assertThat(activities).extracting(ScriptedActivity::observedAt)
                    .allSatisfy(at -> assertThat(at).isBefore(earliestRunTime))
                    .isSorted();
        }
    }

    /** The access history of a protagonist's own project on its learned days is exactly its learned work. */
    @Test
    void theAccessHistoryOfTheLearnedDaysIsTheLearnedWork() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);

        for (CompanyGenerator.Protagonist protagonist : CompanyGenerator.protagonists()) {
            String employee = protagonist.employee();
            var scripted = company.scriptedActivities().stream()
                    .filter(a -> a.employeeKey().equals(employee))
                    .collect(Collectors.groupingBy(a -> LocalDate.ofInstant(a.observedAt(), ZoneOffset.UTC),
                            Collectors.counting()));
            var accessed = company.accessHistory().stream()
                    .filter(a -> a.employeeKey().equals(employee)
                            && a.projectKey().equals(protagonist.project())
                            && !a.accessDate().isBefore(ANCHOR.minusDays(CompanyGenerator.learnedDays(employee))))
                    .collect(Collectors.toMap(a -> a.accessDate(), a -> (long) a.accessCount()));
            assertThat(accessed).as(employee).isEqualTo(scripted);
            assertThat(company.assignments()).extracting(Assignment::employeeKey, Assignment::projectKey)
                    .as(employee).contains(tuple(employee, protagonist.project()));
        }
    }

    /**
     * W2-7: the night-shift administrator works the hours admin A never works, on the same operations project; the
     * field support engineer worked the first learned week from the network of a registered trip of the company and
     * the second from the office. Each protagonist keeps one usual device.
     */
    @Test
    void theBaselineVariantsDifferFromTheirColleaguesInHoursAndNetwork() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);

        assertThat(activitiesOf(company, CompanyBlueprint.ADMIN_NIGHT)).allSatisfy(a -> {
            LocalTime time = LocalTime.ofInstant(a.observedAt(), ZoneOffset.UTC);
            assertThat(time.isBefore(LocalTime.of(4, 0)) || !time.isBefore(LocalTime.of(22, 0))).as(time.toString())
                    .isTrue();
            assertThat(a.clientIp()).isEqualTo("10.40.12.11");
        });
        assertThat(activitiesOf(company, CompanyBlueprint.ADMIN_A)).allSatisfy(a -> {
            LocalTime time = LocalTime.ofInstant(a.observedAt(), ZoneOffset.UTC);
            assertThat(time).isBetween(LocalTime.of(9, 0), LocalTime.of(18, 0));
            assertThat(a.clientIp()).isEqualTo("10.40.12.10");
        });

        TravelPlan trip = company.travelPlans().stream().filter(t -> t.employeeKey().equals(CompanyBlueprint.ENGINEER_FIELD))
                .findFirst().orElseThrow();
        assertThat(company.travelPlans()).hasSize(1);
        assertThat(trip.networkCidr()).isEqualTo(CompanyBlueprint.FIELD_TRIP_NETWORK);
        assertThat(trip.validFrom()).isEqualTo(CompanyCalendar.at(ANCHOR.minusDays(14), LocalTime.MIDNIGHT));
        assertThat(trip.validUntil()).isEqualTo(CompanyCalendar.at(ANCHOR.minusDays(7), LocalTime.MIDNIGHT));
        List<ScriptedActivity> field = activitiesOf(company, CompanyBlueprint.ENGINEER_FIELD);
        assertThat(field).filteredOn(a -> a.observedAt().isBefore(trip.validUntil())).hasSize(25)
                .allSatisfy(a -> assertThat(Networks.contains(trip.networkCidr(), a.clientIp())).isTrue());
        assertThat(field).filteredOn(a -> !a.observedAt().isBefore(trip.validUntil())).hasSize(25)
                .allSatisfy(a -> assertThat(a.clientIp()).isEqualTo("10.40.21.11"));
        assertThat(field).allSatisfy(a -> assertThat(a.operation().equals("EXPORT")
                ? a.targetKey() : a.targetKey().substring(0, 6)).isEqualTo(CompanyBlueprint.FIELD_PROJECT));
        assertThat(activitiesOf(company, CompanyBlueprint.ENGINEER_K))
                .allSatisfy(a -> assertThat(a.clientIp()).isEqualTo("10.40.21.10"));

        Map<String, String> devices = company.devices().stream()
                .collect(Collectors.toMap(Device::employeeKey, Device::userAgent));
        assertThat(devices).containsEntry(CompanyBlueprint.ADMIN_NIGHT, CompanyBlueprint.ADMIN_NIGHT_DEVICE)
                .containsEntry(CompanyBlueprint.ENGINEER_FIELD, CompanyBlueprint.ENGINEER_FIELD_DEVICE)
                .containsEntry(CompanyBlueprint.ADMIN_A, CompanyBlueprint.ADMIN_A_DEVICE)
                .containsEntry(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.ENGINEER_K_DEVICE);
    }

    private static List<ScriptedActivity> activitiesOf(CompanyDataset company, String employee) {
        return company.scriptedActivities().stream().filter(a -> a.employeeKey().equals(employee)).toList();
    }

    @Test
    void engineerKHoldsTheHxOnCallInTheAnchorWeek() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);
        Instant runTime = CompanyCalendar.at(ANCHOR, TimeSlot.DAWN);

        assertThat(company.rosters())
                .filteredOn(r -> r.team().startsWith("HX") && !r.startsAt().isAfter(runTime) && r.endsAt().isAfter(runTime))
                .singleElement()
                .satisfies(r -> assertThat(r.employeeKey()).isEqualTo(CompanyBlueprint.ENGINEER_K));
    }

    @Test
    void theAnchorIsTheLatestWednesdayOnOrBeforeToday() {
        assertThat(CompanyCalendar.anchorFor(LocalDate.of(2026, 10, 5))).isEqualTo(LocalDate.of(2026, 9, 30));
        assertThat(CompanyCalendar.anchorFor(LocalDate.of(2026, 9, 30))).isEqualTo(LocalDate.of(2026, 9, 30));
        assertThat(CompanyCalendar.anchorFor(LocalDate.of(2026, 10, 6))).isEqualTo(LocalDate.of(2026, 9, 30));
    }
}
