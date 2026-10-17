package io.contexa.contexacore.autonomous.baseline;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator.Observation;
import io.contexa.contexacore.autonomous.tiered.prompt.BaselineLineValues;
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
    void anObservationLearnedAfterAVerificationCountsAtItsWeight() {
        List<Observation> whole = new ArrayList<>();
        List<Observation> weighted = new ArrayList<>();
        for (int index = 0; index < 7; index++) {
            whole.add(read(NOW.minusDays(1).withHour(10)));
            weighted.add(read(NOW.minusDays(1).withHour(10)));
        }
        for (int index = 0; index < 2; index++) {
            LocalDateTime night = NOW.minusDays(1).withHour(3);
            whole.add(read(night));
            weighted.add(new Observation(at(night), "READ", "host", false, "INTERNAL", null, "/api/reports/R-3", null,
                    true, null, 0.25));
        }

        // Counted whole, two requests at 03:00 keep 10:00 below 80% of the weight (7 of 9): 03:00 is usual.
        assertThat(calculate(whole).usualHours()).containsExactly(3, 10);
        // W5-2: learned after a verification at a quarter of the weight, they no longer make 03:00 usual (7 of 7.5);
        // they are still observations and the hour is still seen.
        BaselineView view = calculate(weighted);
        assertThat(view.usualHours()).containsExactly(10);
        assertThat(view.seenHours()).containsExactly(3, 10);
        assertThat(view.observations()).isEqualTo(9);
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

    @Test
    void theNetworksDevicesAndLoginsAreCountedFromTheObservationsLikeTheOtherDimensions() {
        List<Observation> history = new ArrayList<>();
        LocalDateTime tuesday = NOW.minusDays(1).withHour(10).withMinute(0);
        for (int index = 0; index < 3; index++) {
            history.add(identified(tuesday.plusMinutes(index * 10L), "10.40.12.0/24", "Chrome/140 on WINDOWS",
                    "PASSWORD"));
        }
        history.add(identified(NOW.minusDays(2).withHour(14), "203.0.113.0/24", "Safari/18 on MAC", "SSO"));
        // An observation stored before W5-9 holds no identity and is not counted for these dimensions.
        history.add(read(NOW.minusDays(2).withHour(15)));

        BaselineView view = calculate(history);

        assertThat(view.counts().networks()).containsExactly(entry("10.40.12.0/24", 3), entry("203.0.113.0/24", 1));
        assertThat(view.counts().devices()).containsExactly(entry("Chrome/140 on WINDOWS", 3), entry("Safari/18 on MAC", 1));
        assertThat(view.counts().logins()).containsExactly(entry("PASSWORD", 3), entry("SSO", 1));
        assertThat(view.counts().identityObservations()).isEqualTo(4);
        assertThat(view.usualNetworks()).containsExactly("10.40.12.0/24", "203.0.113.0/24");
        assertThat(view.usualDevices()).containsExactly("Chrome/140 on WINDOWS", "Safari/18 on MAC");
        assertThat(view.usualBrowsers()).containsExactly("Chrome/140", "Safari/18");
        assertThat(view.usualOperatingSystems()).containsExactly("MAC", "WINDOWS");
        assertThat(view.usualLoginMethods()).containsExactly("PASSWORD", "SSO");
        // W5-9: the long-term baseline adds its state; the three dimensions stay the view's own.
        BaselineView personal = view.withPersonalBaselineState(BaselineView.State.ESTABLISHED, 25L);
        assertThat(personal.state()).isEqualTo(BaselineView.State.ESTABLISHED);
        assertThat(personal.usualNetworks()).isEqualTo(view.usualNetworks());
        assertThat(personal.counts()).isEqualTo(view.counts());
    }

    @Test
    void anObservationHoldingAValueTheVocabularyTableNoLongerReadsIsLeftOutAndCounted() {
        // W5-7 D4: observations of another vocabulary are read through the table (a network learned as a prefix is
        // today's band); one holding a login method today's table reads as nothing is left out of the three dimensions
        // and counted, the others in today's vocabulary as they are.
        List<Observation> history = new ArrayList<>();
        LocalDateTime tuesday = NOW.minusDays(1).withHour(10).withMinute(0);
        history.add(identified(tuesday, "10.40.12.0/24", "Chrome/140 on WINDOWS", "PASSWORD"));
        history.add(new Observation(at(tuesday.plusMinutes(10)), "READ", "host", false, "INTERNAL", null,
                "/api/reports/R-1", null, true, null, 1.0, "10.40.12", "Chrome/140 on Windows 11", "PASSWORD",
                "vocab-2026.01.01"));
        history.add(new Observation(at(tuesday.plusMinutes(20)), "READ", "host", false, "INTERNAL", null,
                "/api/reports/R-2", null, true, null, 1.0, "10.40.12.0/24", "Chrome/140 on WINDOWS", "FACE_SCAN",
                "vocab-2026.01.01"));

        BaselineView view = calculate(history);

        assertThat(view.counts().networks()).containsExactly(entry("10.40.12.0/24", 2));
        assertThat(view.counts().devices()).containsExactly(entry("Chrome/140 on WINDOWS", 2));
        assertThat(view.counts().logins()).containsExactly(entry("PASSWORD", 2));
        assertThat(view.counts().identityObservations()).isEqualTo(2);
        assertThat(view.counts().vocabularyNotComparable()).isEqualTo(1);
        // The other dimensions read the observation as before.
        assertThat(view.observations()).isEqualTo(3);
    }

    @Test
    void aPasswordStoredBeforeTheLoginKeptEveryMethodIsNotComparable() {
        // W5-10 D6 with W5-7 D4: an observation of the first vocabulary holding PASSWORD may have been a login with a
        // second factor; it is left out of the three dimensions and counted.
        List<Observation> history = new ArrayList<>();
        LocalDateTime tuesday = NOW.minusDays(1).withHour(10).withMinute(0);
        history.add(identified(tuesday, "10.40.12.0/24", "Chrome/140 on WINDOWS", "PASSWORD+ONE_TIME_CODE"));
        history.add(new Observation(at(tuesday.plusMinutes(10)), "READ", "host", false, "INTERNAL", null,
                "/api/reports/R-1", null, true, null, 1.0, "10.40.12.0/24", "Chrome/140 on WINDOWS", "PASSWORD",
                "vocab-2026.10.15"));

        BaselineView view = calculate(history);

        assertThat(view.counts().logins()).containsExactly(entry("PASSWORD+ONE_TIME_CODE", 1));
        assertThat(view.counts().vocabularyNotComparable()).isEqualTo(1);
    }

    @Test
    void theRequestsOwnValuesAreCountedWithTheirDaysAndTheirFirstAndLastTimes() {
        // W5-10 D1~D3: for the request's own value of each dimension, how many of the window's observations holding
        // the dimension held it, on how many of their dates, first and last; a value the window does not hold reads its
        // last time in the retention, or none when it was never seen.
        List<Observation> history = new ArrayList<>();
        for (int day = 1; day <= 6; day++) {
            LocalDateTime morning = LocalDateTime.of(2026, 10, day, 10, 0);
            history.add(identified(morning, "10.40.12.0/24", "Chrome/140 on WINDOWS", "PASSWORD"));
            history.add(identified(morning.plusMinutes(30), "10.40.12.0/24", "Chrome/140 on WINDOWS", "PASSWORD"));
        }
        LocalDateTime earlier = LocalDateTime.of(2026, 9, 20, 3, 0);
        history.add(identified(earlier, "203.0.113.0/24", "Chrome/140 on WINDOWS", "PASSWORD"));
        Observation request = new Observation(at(NOW), "READ", "host", false, "INTERNAL", null, "/api/reports/R-3",
                null, true, null, 1.0, "203.0.113.0/24", "Chrome/140 on WINDOWS", "PASSWORD");

        BaselineView view = BaselineViewCalculator.calculate(history, at(NOW), UTC, request);
        Map<String, BaselineView.Seen> seen = view.counts().request();

        // The window is the last 7 days (12 observations on 6 dates); 09-20 is in the retention only.
        assertThat(seen.get("TIME")).isEqualTo(new BaselineView.Seen("03", 0, 12, 0, 6, null, null, at(earlier)));
        assertThat(seen.get("NETWORK"))
                .isEqualTo(new BaselineView.Seen("203.0.113.0/24", 0, 12, 0, 6, null, null, at(earlier)));
        assertThat(seen.get("DEVICE")).isEqualTo(new BaselineView.Seen("Chrome/140 on WINDOWS", 12, 12, 6, 6,
                at(LocalDateTime.of(2026, 10, 1, 10, 0)), at(LocalDateTime.of(2026, 10, 6, 10, 30)),
                at(LocalDateTime.of(2026, 10, 6, 10, 30))));
        // The day of the week reads several weeks (W2-5): 13 observations on 7 dates, never a Wednesday.
        assertThat(seen.get("DAY")).isEqualTo(new BaselineView.Seen("Wed", 0, 13, 0, 7, null, null, null));
        // The request itself is not part of the view.
        assertThat(view.observations()).isEqualTo(12);
    }

    @Test
    void theUsualRateIsTheMedianAndTheNinetyFifthPercentileOfTheCountsOfTheHourUpToEachRequest() {
        // N-RATE-1 (W5-10 D5): each request of the window counts the window's requests of the 60 minutes up to it, as
        // the decision facts count the request being judged. Five days hold 1, 2, 2, 3 and 10 requests a minute apart:
        // the counts are 1; 1, 2; 1, 2; 1, 2, 3; and 1 to 10, so 18 counts of median 3 and 95th percentile 10.
        List<Observation> history = new ArrayList<>();
        int[] perHour = {1, 2, 2, 3, 10};
        for (int slot = 0; slot < perHour.length; slot++) {
            LocalDateTime hour = NOW.minusDays(1 + slot).withHour(10).withMinute(0);
            for (int index = 0; index < perHour[slot]; index++) {
                history.add(read(hour.plusMinutes(index)));
            }
        }

        assertThat(calculate(history).counts().rate()).isEqualTo(new BaselineView.Rate(18, 3, 10));
    }

    @Test
    void theUsualRateLineStatesTheCountsOfTheHourUpToEachRequestAndHowManyWereCounted() {
        // N-RATE-1: the line states the definition the decision facts compare the request's rate with.
        List<Observation> history = new ArrayList<>();
        int[] perHour = {1, 2, 2, 3, 10};
        for (int slot = 0; slot < perHour.length; slot++) {
            LocalDateTime hour = NOW.minusDays(1 + slot).withHour(10).withMinute(0);
            for (int index = 0; index < perHour[slot]; index++) {
                history.add(read(hour.plusMinutes(index)));
            }
        }

        assertThat(BaselineLineValues.of(calculate(history)).get("UsualRequestRate"))
                .isEqualTo("median 3, 95th percentile 10 requests in the 60 min up to a request (18 requests)");
    }

    /**
     * N-RATE-1, administrator A's week (seal 9134): requests at 11:25, 11:59 and 12:07 of one day, 42 minutes, and
     * single requests hours apart. By clock hours the three were 2 and 1, so the usual 95th percentile was 2 while the
     * decision facts counted 3 in the 60 minutes up to 12:07; counted the same way, the usual 95th percentile is 3.
     */
    @Test
    void threeRequestsWithinFortyTwoMinutesAcrossAClockHourAreAUsualThreeInTheHourUpToARequest() {
        BaselineView view = calculate(administratorAWeek());

        assertThat(view.counts().rate()).isEqualTo(new BaselineView.Rate(18, 1, 3));
        assertThat(BaselineLineValues.of(view).get("UsualRequestRate"))
                .isEqualTo("median 1, 95th percentile 3 requests in the 60 min up to a request (18 requests)");
        // The clock hour that held the most requests is a count of its own (W2-5), not the usual rate.
        assertThat(view.counts().busiestActiveHourRequests()).isEqualTo(2);
    }

    /**
     * N-RATE-1: a view sealed before holds a rate of clock hours ({"activeHours":17,...}): its median and 95th
     * percentile are of another definition and it counted no request, so the view read again holds no usual rate and
     * draws no rate line (the dictionary's missing notation stands); a rate of this definition reads as it was written.
     */
    @Test
    void aRateSealedUnderTheClockHourDefinitionReadsAsNoUsualRateAndDrawsNoRateLine() throws Exception {
        ObjectMapper json = new ObjectMapper();
        BaselineView view = calculate(administratorAWeek());
        String written = json.writeValueAsString(view);
        String clockHours = written.replace("\"requests\":" + view.counts().rate().requests(), "\"activeHours\":17");

        BaselineView sealed = json.readValue(clockHours, BaselineView.class);

        assertThat(json.readValue(written, BaselineView.class).counts().rate()).isEqualTo(view.counts().rate());
        assertThat(sealed.observed()).isTrue();
        assertThat(sealed.counts().rate()).isNull();
        assertThat(BaselineLineValues.of(sealed)).doesNotContainKey("UsualRequestRate");
        assertThat(BaselineLineValues.of(sealed).values()).noneMatch(line -> line.contains("percentile"));
    }

    /** Administrator A's week: 11:25, 11:59 and 12:07 of one day, and fifteen single requests two hours apart. */
    private static List<Observation> administratorAWeek() {
        LocalDateTime day = NOW.minusDays(3);
        List<Observation> history = new ArrayList<>(List.of(read(day.withHour(11).withMinute(25)),
                read(day.withHour(11).withMinute(59)), read(day.withHour(12).withMinute(7))));
        for (int days = 1; days <= 5; days++) {
            for (int hour = 14; hour <= 18; hour += 2) {
                history.add(read(NOW.minusDays(days).withHour(hour).withMinute(0)));
            }
        }
        return history;
    }

    private static Observation identified(LocalDateTime time, String network, String device, String login) {
        return new Observation(at(time), "READ", "host", false, "INTERNAL", null, "/api/reports/R-" + time.getHour(),
                null, true, null, 1.0, network, device, login);
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
