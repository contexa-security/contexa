package io.contexa.showcase.business.company;

import io.contexa.showcase.business.company.CompanyDataset.Assignment;
import io.contexa.showcase.business.company.CompanyDataset.Employee;
import io.contexa.showcase.business.company.CompanyDataset.ScriptedActivity;
import org.junit.jupiter.api.Test;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
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

    @Test
    void protagonistsHaveTwentyFiveLearnedRequestsOnTheFiveWorkdaysOfThePreviousWeek() {
        CompanyDataset company = generator.generate(20261005L, ANCHOR);
        assertThat(ANCHOR.getDayOfWeek()).isEqualTo(DayOfWeek.WEDNESDAY);

        for (String protagonist : Set.of(CompanyBlueprint.ADMIN_A, CompanyBlueprint.ENGINEER_K)) {
            var activities = company.scriptedActivities().stream()
                    .filter(a -> a.employeeKey().equals(protagonist)).toList();
            Set<LocalDate> days = activities.stream()
                    .map(a -> LocalDate.ofInstant(a.observedAt(), ZoneOffset.UTC))
                    .collect(Collectors.toSet());
            assertThat(activities).as(protagonist).hasSize(25);
            assertThat(days).as(protagonist).hasSize(5).allSatisfy(day -> {
                assertThat(day).isBefore(ANCHOR).isAfterOrEqualTo(ANCHOR.minusDays(7));
                assertThat(CompanyCalendar.isWorkday(day)).isTrue();
            });
            assertThat(days).as("the run's weekday is a usual workday").anyMatch(day -> day.getDayOfWeek() == ANCHOR.getDayOfWeek());
            Instant earliestRunTime = CompanyCalendar.at(ANCHOR, TimeSlot.DAWN);
            assertThat(activities).extracting(ScriptedActivity::observedAt)
                    .allSatisfy(at -> assertThat(at).isBefore(earliestRunTime))
                    .isSorted();
        }
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
