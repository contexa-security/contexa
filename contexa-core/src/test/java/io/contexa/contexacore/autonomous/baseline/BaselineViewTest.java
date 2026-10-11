package io.contexa.contexacore.autonomous.baseline;

import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator.Observation;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

/** W2-3: one window, one decay and one rule for what is usual, with the evidence grade and its causes. */
class BaselineViewTest {

    private static final ZoneId UTC = ZoneOffset.UTC;
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 7, 3, 17);

    @Test
    void theLastSevenDaysDescribeTheSubjectOnlyWithTheMinimumSample() {
        List<Observation> history = new ArrayList<>();
        for (int day = 1; day <= 4; day++) {
            history.add(read(NOW.minusDays(day).withHour(10)));
        }
        for (int day = 8; day <= 23; day++) {
            history.add(read(NOW.minusDays(day).withHour(11)));
        }

        BaselineView view = calculate(history);

        // A-19: four observations in the last week no longer stand for the subject; the month does.
        assertThat(view.windowDays()).isEqualTo(30);
        assertThat(view.observations()).isEqualTo(20);
        assertThat(view.windowBasis()).isEqualTo(
                "the last 7 days hold 4 observations, below the minimum 10; the view uses the last 30 days");
        assertThat(view.evidenceCauses()).contains(view.windowBasis());

        for (int day = 1; day <= 6; day++) {
            history.add(read(NOW.minusDays(day).withHour(9)));
        }
        assertThat(calculate(history).windowDays()).isEqualTo(7);
    }

    @Test
    void oldHoursFadeFromTheUsualHoursButStaySeen() {
        List<Observation> history = new ArrayList<>();
        for (int day = 24; day <= 29; day++) {
            history.add(read(NOW.minusDays(day).withHour(3)));
        }
        for (int index = 0; index < 9; index++) {
            history.add(read(NOW.minusDays(1).withHour(10)));
        }

        BaselineView view = calculate(history);

        // H-9: six requests at 03:00 a month ago weigh about a quarter each; nine at 10:00 yesterday carry over 80% of
        // the weight. By count alone (9 of 15) 03:00 would still be usual. Every hour stays seen, in order (E-1).
        assertThat(view.windowDays()).isEqualTo(30);
        assertThat(view.usualHours()).containsExactly(10);
        assertThat(view.seenHours()).containsExactly(3, 10);
    }

    @Test
    void theTargetsAreTheTemplateVariablesOfTheRequestPath() {
        assertThat(BaselineViewCalculator.target("/api/projects/{projectKey}/exports", "/api/projects/PLM-OPS/exports"))
                .isEqualTo("projectKey=PLM-OPS");
        assertThat(BaselineViewCalculator.target("/api/documents/{documentKey}", "/api/customers/CUS-1")).isNull();
        assertThat(BaselineViewCalculator.target(null, "/api/projects/PLM-OPS/exports")).isNull();

        List<Observation> history = new ArrayList<>();
        for (int index = 0; index < 12; index++) {
            history.add(new Observation(at(NOW.minusDays(1 + index % 3).withHour(10)), "EXPORT", "protectableMethod",
                    true, "INTERNAL", "/api/projects/{projectKey}/exports",
                    "/api/projects/" + (index < 11 ? "PLM-OPS" : "HX-200") + "/exports", null, true));
        }
        assertThat(calculate(history).usualTargets()).containsExactly("projectKey=PLM-OPS");

        // A document read once is not a usual target, however many such reads there are.
        List<Observation> documents = new ArrayList<>();
        for (int index = 0; index < 12; index++) {
            documents.add(new Observation(at(NOW.minusDays(1).withHour(10)), "READ", "protectableMethod", true,
                    "INTERNAL", "/api/documents/{documentKey}", "/api/documents/D-" + index, null, true));
        }
        assertThat(calculate(documents).usualTargets()).isEmpty();
    }

    @Test
    void actionsAreCountedInOneVocabularyWithTheirShares() {
        List<Observation> history = new ArrayList<>();
        for (int index = 0; index < 20; index++) {
            history.add(observation(NOW.minusDays(1).withHour(10), "READ", "host", false));
        }
        for (int index = 0; index < 4; index++) {
            history.add(observation(NOW.minusDays(1).withHour(11), "EXPORT", "host", false));
        }
        history.add(observation(NOW.minusDays(1).withHour(12), "ADMIN", "host", false));

        BaselineView view = calculate(history);

        assertThat(view.actionCounts()).containsExactly(Map.entry("READ", 20), Map.entry("EXPORT", 4), Map.entry("ADMIN", 1));
        assertThat(view.readWriteExportRatio()).isEqualTo("83:0:17");
        assertThat(view.privilegedActions()).isEqualTo(1);
        assertThat(view.knownRareTasks()).containsExactly("ADMIN /api/reports/{id} (1)");
        assertThat(view.requestsPerActiveHour()).isEqualTo(8.33);
        assertThat(view.evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.STRONG);
        assertThat(view.evidenceCauses()).isEmpty();
        assertThat(view.workProfileEvidenceState()).isEqualTo("TRUSTED");

        // Another caution of the same work profile is a cause too: the state never says TRUSTED beside a caution.
        BaselineView cautioned = view.withAdditionalCauses(List.of("workProfile.protectableInvocationDensity needs caution"));
        assertThat(cautioned.evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.LIMITED);
        assertThat(cautioned.workProfileEvidenceState()).isEqualTo("PROVISIONAL");
        assertThat(cautioned.evidenceSummary()).isEqualTo("LIMITED: workProfile.protectableInvocationDensity needs caution");
    }

    @Test
    void theEvidenceGradeSaysItsCause() {
        List<Observation> inferred = new ArrayList<>();
        for (int index = 0; index < 25; index++) {
            inferred.add(observation(NOW.minusDays(1 + index % 5).withHour(10), "READ", "protectableMethod", true));
        }
        BaselineView limited = calculate(inferred);
        // S-21: a work profile read from method names is limited, and the view says so with the count.
        assertThat(limited.evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.LIMITED);
        assertThat(limited.evidenceCauses())
                .containsExactly("action family inferred from protectableMethod in 25 of 25 observations");

        List<Observation> fromHttpMethod = new ArrayList<>();
        for (int index = 0; index < 25; index++) {
            fromHttpMethod.add(observation(NOW.minusDays(1).withHour(10), "WRITE", "httpMethod", true));
        }
        assertThat(calculate(fromHttpMethod).evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.WEAK);

        BaselineView thin = calculate(inferred.subList(0, 3));
        assertThat(thin.evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.WEAK);
        assertThat(thin.evidenceCauses()).first().isEqualTo("only 3 observations in the window, below the minimum 10");
    }

    @Test
    void theUsualSessionLengthIsTheMedianSpanOfSessionsWithTwoOrMoreRequests() {
        List<Observation> history = new ArrayList<>();
        LocalDateTime start = NOW.minusDays(1).withHour(9).withMinute(0);
        history.add(inSession(start, "s1"));
        history.add(inSession(start.plusMinutes(30), "s1"));
        history.add(inSession(start.plusHours(2), "s2"));
        history.add(inSession(start.plusHours(2).plusMinutes(10), "s2"));
        history.add(inSession(start.plusHours(3), "s3"));
        history.add(inSession(start.plusHours(4), "s4"));
        history.add(inSession(start.plusHours(4).plusMinutes(25), "s4"));
        history.add(inSession(start.plusHours(4).plusMinutes(50), "s4"));

        assertThat(calculate(history).usualSessionMinutes()).isEqualTo(30);

        // A session key used again the next day is two activity periods, not a session of a day and a half.
        LocalDateTime dayBefore = start.minusDays(1);
        List<Observation> reused = List.of(
                inSession(dayBefore, "s1"), inSession(dayBefore.plusMinutes(20), "s1"),
                inSession(start, "s1"), inSession(start.plusMinutes(25), "s1"),
                inSession(start.plusHours(3), "s2"), inSession(start.plusHours(3).plusMinutes(10), "s2"));
        assertThat(calculate(reused).usualSessionMinutes()).isEqualTo(20);

        // Two periods are too few to say what is usual.
        assertThat(calculate(reused.subList(0, 4)).usualSessionMinutes()).isNull();
    }

    @Test
    void theUsualExportSizeComesFromTheExportsThatStatedTheirCount() {
        List<Observation> history = new ArrayList<>();
        int[] counts = {40, 60, 25};
        for (int index = 0; index < counts.length; index++) {
            history.add(new Observation(at(NOW.minusDays(1 + index).withHour(10)), "EXPORT", "host", false, "INTERNAL",
                    "/api/projects/{projectKey}/exports", "/api/projects/PLM-OPS/exports", null, true, counts[index]));
        }
        history.add(new Observation(at(NOW.minusDays(1).withHour(11)), "EXPORT", "host", false, "INTERNAL",
                "/api/projects/{projectKey}/exports", "/api/projects/PLM-OPS/exports", null, true));
        history.add(new Observation(at(NOW.minusDays(1).withHour(12)), "READ", "host", false, "INTERNAL", null,
                "/api/reports/R-1", null, true, 900));

        // W2-6: three exports said their count (25, 40, 60); an export without one and a read do not count.
        assertThat(calculate(history).exportSize()).isEqualTo(new BaselineView.ExportSize(3, 40, 60));
        assertThat(calculate(history.subList(3, 5)).exportSize()).isNull();
    }

    @Test
    void theActivityPeriodBeingJudgedIsNotPartOfTheUsualBehaviour() {
        Observation older = inSession(NOW.minusMinutes(80), "s1");
        Observation chained = inSession(NOW.minusMinutes(45), "s1");
        Observation last = inSession(NOW.minusMinutes(20), "s1");
        Observation other = inSession(NOW.minusMinutes(5), "s2");
        List<Observation> history = List.of(older, chained, last, other);

        // 20 and 45 minutes ago lead up to now with pauses of at most 30 minutes; 80 minutes ago ended an earlier
        // period of the same session key, and another session is not the period being judged.
        assertThat(BaselineViewCalculator.withoutCurrentPeriod(history, Observation::timestampMs,
                Observation::sessionKey, "s1", at(NOW))).containsExactly(older, other);
        assertThat(BaselineViewCalculator.withoutCurrentPeriod(history, Observation::timestampMs,
                Observation::sessionKey, null, at(NOW))).isEqualTo(history);
    }

    @Test
    void theViewCountsHowOftenEachHourDayAndTargetWasSeenAndTheBusiestHour() {
        List<Observation> history = new ArrayList<>();
        LocalDateTime tuesday = NOW.minusDays(1).withHour(10).withMinute(0);
        for (int index = 0; index < 3; index++) {
            history.add(new Observation(at(tuesday.plusMinutes(index * 10L)), "EXPORT", "host", false, "INTERNAL",
                    "/api/projects/{projectKey}/exports", "/api/projects/PLM-OPS/exports", null, true));
        }
        history.add(new Observation(at(NOW.minusDays(2).withHour(14)), "EXPORT", "host", false, "INTERNAL",
                "/api/projects/{projectKey}/exports", "/api/projects/HX-200/exports", null, true));

        BaselineView view = calculate(history);

        // W2-5: a decision fact says how often a value was seen ("time 03 seen 0 of 4").
        assertThat(view.counts().hours()).containsExactly(entry(10, 3), entry(14, 1));
        assertThat(view.counts().days()).containsExactly(entry(1, 1), entry(2, 3));
        assertThat(view.counts().targets()).containsExactly(entry("projectKey=HX-200", 1),
                entry("projectKey=PLM-OPS", 3));
        assertThat(view.counts().busiestActiveHourRequests()).isEqualTo(3);
        assertThat(view.withAdditionalCauses(List.of("a cause")).counts()).isEqualTo(view.counts());
        assertThat(view.withPersonalBaseline(BaselineView.State.ESTABLISHED, 25L, List.of(), List.of(), List.of(),
                List.of(), List.of()).counts()).isEqualTo(view.counts());
        assertThat(calculate(List.of()).counts()).isEqualTo(BaselineView.Counts.NONE);
    }

    @Test
    void aDayAsFrequentAsTheUsualOnesIsUsualThoughTheDecayMakesItLightest() {
        // Sealed package 4087: five requests on each weekday of the last week, judged on a Wednesday at 03:17. The
        // Wednesday a week ago is the oldest and weighs least, yet it was seen as often as every usual day.
        List<Observation> history = new ArrayList<>();
        for (int day = 1; day <= 7; day++) {
            LocalDateTime date = NOW.minusDays(day);
            if (date.getDayOfWeek().getValue() > 5) {
                continue;
            }
            for (int hour = 10; hour <= 14; hour++) {
                history.add(read(date.withHour(hour).withMinute(0)));
            }
        }

        BaselineView view = calculate(history);

        assertThat(view.windowDays()).isEqualTo(7);
        assertThat(view.observations()).isEqualTo(25);
        assertThat(view.usualDays()).containsExactly(1, 2, 3, 4, 5);
        assertThat(view.usualHours()).containsExactly(10, 11, 12, 13, 14);
    }

    @Test
    void theDayOfTheWeekReadsSeveralWeeksWhileTheOtherDimensionsReadTheWindow() {
        List<Observation> history = new ArrayList<>();
        for (int index = 0; index < 6; index++) {
            history.add(read(NOW.minusDays(1).withHour(10).withMinute(index)));
            history.add(read(NOW.minusDays(2).withHour(10).withMinute(index)));
        }
        history.add(read(NOW.minusDays(14).withHour(16)));
        history.add(read(NOW.minusDays(21).withHour(16)));

        BaselineView view = calculate(history);

        // A Wednesday comes once a week: the two Wednesdays of earlier weeks are seen days, the 16:00 hours of those
        // days are outside the 7-day window the hours read.
        assertThat(view.windowDays()).isEqualTo(7);
        assertThat(view.observations()).isEqualTo(12);
        assertThat(view.seenHours()).containsExactly(10);
        assertThat(view.seenDays()).containsExactly(1, 2, 3);
        assertThat(view.usualDays()).containsExactly(1, 2);
        assertThat(view.counts().days()).containsExactly(entry(1, 6), entry(2, 6), entry(3, 2));
        assertThat(view.counts().dayObservations()).isEqualTo(14);
    }

    @Test
    void theActivityPeriodBeingJudgedIncludesTheSessionsRequestsUnderAnEarlierKey() {
        List<Observation> history = new ArrayList<>();
        history.add(inSession(NOW.minusDays(1).withHour(10), "key-old"));
        history.add(inSession(NOW.minusMinutes(5), "key-old"));
        history.add(inSession(NOW.minusMinutes(2), "key-new"));

        // A step-up check replaced the session id 3 minutes ago: the request 5 minutes ago is the same period
        // (P2 correction 5); yesterday's request of the same session key is not.
        List<Observation> usual = BaselineViewCalculator.withoutCurrentSessionPeriod(history,
                Observation::timestampMs, Observation::sessionKey, List.of("key-new", "key-old"), at(NOW));
        assertThat(usual).hasSize(1);
        assertThat(BaselineViewCalculator.withoutCurrentPeriod(history, Observation::timestampMs,
                Observation::sessionKey, "key-new", at(NOW))).hasSize(2);
    }

    @Test
    void noObservationIsAWeakViewThatSaysWhy() {
        BaselineView view = calculate(List.of());

        assertThat(view.observed()).isFalse();
        assertThat(view.state()).isEqualTo(BaselineView.State.NONE);
        assertThat(view.evidenceGrade()).isEqualTo(BaselineView.EvidenceGrade.WEAK);
        assertThat(view.evidenceCauses()).containsExactly("no observation confirmed after a decision in the last 30 days");
        BaselineView personal = view.withPersonalBaseline(BaselineView.State.ESTABLISHED, 25L, List.of("10.40.12.0/24"),
                List.of("Chrome/140 on WINDOWS"), List.of("Chrome/140"), List.of("WINDOWS"), List.of("PASSWORD"));
        assertThat(personal.state()).isEqualTo(BaselineView.State.ESTABLISHED);
        assertThat(personal.usualDevices()).containsExactly("Chrome/140 on WINDOWS");
    }

    private static BaselineView calculate(List<Observation> history) {
        return BaselineViewCalculator.calculate(history, at(NOW), UTC);
    }

    private static Observation read(LocalDateTime time) {
        return observation(time, "READ", "host", false);
    }

    private static Observation observation(LocalDateTime time, String family, String source, boolean inferred) {
        return new Observation(at(time), family, source, inferred, "INTERNAL", null, "/api/reports/R-" + time.getHour(),
                null, true);
    }

    private static Observation inSession(LocalDateTime time, String session) {
        return new Observation(at(time), "READ", "host", false, "INTERNAL", null, "/api/reports", session, true);
    }

    private static long at(LocalDateTime time) {
        return time.toInstant(ZoneOffset.UTC).toEpochMilli();
    }
}
