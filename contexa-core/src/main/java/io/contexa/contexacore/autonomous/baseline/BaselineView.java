/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.baseline;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The usual behaviour of one subject, dimension by dimension. The dimensions of time, target and action come from the
 * observations confirmed after decisions, within one window and with a decay (see {@link BaselineViewCalculator});
 * networks, browsers, operating systems and login methods come from the long-term personal baseline. The observations
 * leave out the activity period of the request being judged, which is what the view is compared with. Every place that
 * says what is usual for the subject reads this one view, so a prompt never shows two usual pictures of the same
 * subject.
 *
 * @param state                 how much of the personal baseline is learned: ESTABLISHED, PROVISIONAL or NONE
 * @param learnedUpdates        the requests the personal baseline learned, null when unknown
 * @param observations          the observations in the window
 * @param daysCovered           the calendar days (event clock) the window's observations fall on
 * @param windowDays            7, or 30 when the last 7 days hold fewer observations than the minimum sample
 * @param windowBasis           why the window is what it is
 * @param usualHours            the hours carrying most of the decayed weight, ascending
 * @param seenHours             every hour of the window, ascending
 * @param usualDays             the days of the week (1 Monday to 7 Sunday) carrying most of the weight, ascending;
 *                              read from the last {@code BaselineViewCalculator.DAY_OF_WEEK_DAYS} days, since a
 *                              day of the week comes once a week
 * @param seenDays              every day of the week of those days, ascending
 * @param usualTargets          the URL template bindings ({@code projectKey=PLM-OPS}) seen at least twice and
 *                              carrying most of their weight
 * @param actionCounts          observations per action family, in the order of {@code ActionFamily}
 * @param readWriteExportRatio  read, write and export shares in percent ({@code 80:0:20}), null without any
 * @param exportSize            the item counts of the window's exports that stated theirs, null when none did (W2-6)
 * @param resourceClasses       observations per resource class, the most frequent first ({@code INTERNAL=25})
 * @param requestsPerActiveHour observations per hour in which the subject made at least one, see
 *                              {@link #REQUEST_RATE_UNIT}
 * @param usualSessionMinutes   the median length of the subject's activity periods with two or more observations
 *                              (a session idle longer than 30 minutes starts a new period), null with fewer than
 *                              three such periods
 * @param privilegedActions     the ADMIN observations of the window
 * @param knownRareTasks        allowed action and path combinations seen at most twice in a large enough window
 * @param usualNetworks         the networks of the personal baseline, as /24 bands (W2-4)
 * @param usualDevices          the devices of the personal baseline, each a browser on an operating system; empty
 *                              for a baseline learned before device pairs, whose browsers and systems stand apart
 * @param evidenceGrade         how far the view can be relied on
 * @param evidenceCauses        why the grade is not STRONG, each with its count
 * @param counts                how many observations of the window fell on each hour, day and target, and the most
 *                              made in one active hour (W2-5), so a comparison can say how often a value was seen
 */
public record BaselineView(
        State state,
        Long learnedUpdates,
        int observations,
        int daysCovered,
        int windowDays,
        String windowBasis,
        List<Integer> usualHours,
        List<Integer> seenHours,
        List<Integer> usualDays,
        List<Integer> seenDays,
        List<String> usualTargets,
        Map<String, Integer> actionCounts,
        String readWriteExportRatio,
        ExportSize exportSize,
        List<String> resourceClasses,
        Double requestsPerActiveHour,
        Integer usualSessionMinutes,
        int privilegedActions,
        List<String> knownRareTasks,
        List<String> usualNetworks,
        List<String> usualDevices,
        List<String> usualBrowsers,
        List<String> usualOperatingSystems,
        List<String> usualLoginMethods,
        EvidenceGrade evidenceGrade,
        List<String> evidenceCauses,
        Counts counts) {

    public static final String REQUEST_RATE_UNIT = "requests per active hour";

    /** Why no seasonal pattern is stated: the store keeps 30 days of observations and the baseline no time series. */
    public static final String SEASONAL_PATTERN_BASIS =
            "not computed: the observations cover at most 30 days, too short to show a seasonal pattern";

    public enum State {
        ESTABLISHED,
        PROVISIONAL,
        NONE
    }

    public enum EvidenceGrade {
        STRONG,
        LIMITED,
        WEAK
    }

    /**
     * The usual size of the subject's exports.
     *
     * @param exports      the exports that stated their item count
     * @param medianItems  the lower median of their item counts
     * @param largestItems the largest item count
     */
    public record ExportSize(int exports, int medianItems, int largestItems) {
    }

    /**
     * How often the window's observations fell on each value of a dimension (W2-5).
     *
     * @param hours                     observations per hour of the day (0 to 23), event clock
     * @param days                      observations per day of the week (1 Monday to 7 Sunday) in the days the day
     *                                  of the week is read from
     * @param targets                   observations per URL template binding ({@code projectKey=PLM-OPS})
     * @param busiestActiveHourRequests the most observations made within one clock hour
     * @param dayObservations           the observations the day counts were taken from
     * @param networks                  observations per network band of the request (W5-9)
     * @param devices                   observations per device of the request, a browser on a system (W5-9)
     * @param logins                    observations per login method of the request (W5-9)
     * @param identityObservations      the window's observations that hold the request's identity, the count the
     *                                  three dimensions above are read against (observations stored before W5-9
     *                                  hold none)
     * @param vocabularyNotComparable   the window's observations left out of the three dimensions because they hold
     *                                  a value of an earlier vocabulary the vocabulary table no longer reads (W5-7)
     * @param request                   how the request's own value of each dimension was seen, by dimension name
     *                                  ({@code TIME}, {@code DAY}, {@code NETWORK}, ...; W5-10 D1~D3)
     */
    public record Counts(
            Map<Integer, Integer> hours,
            Map<Integer, Integer> days,
            Map<String, Integer> targets,
            int busiestActiveHourRequests,
            int dayObservations,
            Map<String, Integer> networks,
            Map<String, Integer> devices,
            Map<String, Integer> logins,
            int identityObservations,
            int vocabularyNotComparable,
            Map<String, Seen> request,
            Rate rate) {

        public static final Counts NONE = new Counts(Map.of(), Map.of(), Map.of(), 0, 0);

        /** Counts without the rate of the active hours (before W5-10 D5). */
        public Counts(Map<Integer, Integer> hours, Map<Integer, Integer> days, Map<String, Integer> targets,
                      int busiestActiveHourRequests, int dayObservations, Map<String, Integer> networks,
                      Map<String, Integer> devices, Map<String, Integer> logins, int identityObservations,
                      int vocabularyNotComparable, Map<String, Seen> request) {
            this(hours, days, targets, busiestActiveHourRequests, dayObservations, networks, devices, logins,
                    identityObservations, vocabularyNotComparable, request, null);
        }

        /** Counts without the request's own values (before W5-10). */
        public Counts(Map<Integer, Integer> hours, Map<Integer, Integer> days, Map<String, Integer> targets,
                      int busiestActiveHourRequests, int dayObservations, Map<String, Integer> networks,
                      Map<String, Integer> devices, Map<String, Integer> logins, int identityObservations,
                      int vocabularyNotComparable) {
            this(hours, days, targets, busiestActiveHourRequests, dayObservations, networks, devices, logins,
                    identityObservations, vocabularyNotComparable, Map.of());
        }

        /** Counts of observations all in today's vocabulary. */
        public Counts(Map<Integer, Integer> hours, Map<Integer, Integer> days, Map<String, Integer> targets,
                      int busiestActiveHourRequests, int dayObservations, Map<String, Integer> networks,
                      Map<String, Integer> devices, Map<String, Integer> logins, int identityObservations) {
            this(hours, days, targets, busiestActiveHourRequests, dayObservations, networks, devices, logins,
                    identityObservations, 0);
        }

        /** Counts without the request identity dimensions (before W5-9). */
        public Counts(Map<Integer, Integer> hours, Map<Integer, Integer> days, Map<String, Integer> targets,
                      int busiestActiveHourRequests, int dayObservations) {
            this(hours, days, targets, busiestActiveHourRequests, dayObservations, Map.of(), Map.of(), Map.of(), 0);
        }

        /** Counts whose days come from the window itself, as before the day of the week read several weeks. */
        public Counts(Map<Integer, Integer> hours, Map<Integer, Integer> days, Map<String, Integer> targets,
                      int busiestActiveHourRequests) {
            this(hours, days, targets, busiestActiveHourRequests,
                    days == null ? 0 : days.values().stream().mapToInt(Integer::intValue).sum());
        }

        public Counts {
            hours = hours == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(hours));
            days = days == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(days));
            targets = targets == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(targets));
            networks = networks == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(networks));
            devices = devices == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(devices));
            logins = logins == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(logins));
            request = request == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(request));
        }
    }

    /**
     * How the request's own value of one dimension was seen (W5-10 D1~D3).
     *
     * @param value          the request's value as the line names it ({@code 03}, {@code Wed}, a network band)
     * @param seen           the observations of the dimension's read that held it (k)
     * @param of             the observations of that read that hold the dimension (N)
     * @param days           the company dates of that read it was seen on (d)
     * @param ofDays         the company dates of that read that hold the dimension (D)
     * @param firstMs        its first observation in that read, null when not seen there
     * @param lastMs         its last observation in that read, null when not seen there
     * @param retainedLastMs its last observation in the retention, null when it was never seen there
     */
    public record Seen(String value, int seen, int of, int days, int ofDays, Long firstMs, Long lastMs,
                       Long retainedLastMs) {
    }

    /**
     * The requests of each active clock hour of the window (W5-10 D5): how many hours had a request, and the median and
     * the 95th percentile of their requests.
     */
    public record Rate(int activeHours, int median, int p95) {
    }

    /** A view without counts, as before W2-5. */
    public BaselineView(
            State state,
            Long learnedUpdates,
            int observations,
            int daysCovered,
            int windowDays,
            String windowBasis,
            List<Integer> usualHours,
            List<Integer> seenHours,
            List<Integer> usualDays,
            List<Integer> seenDays,
            List<String> usualTargets,
            Map<String, Integer> actionCounts,
            String readWriteExportRatio,
            ExportSize exportSize,
            List<String> resourceClasses,
            Double requestsPerActiveHour,
            Integer usualSessionMinutes,
            int privilegedActions,
            List<String> knownRareTasks,
            List<String> usualNetworks,
            List<String> usualDevices,
            List<String> usualBrowsers,
            List<String> usualOperatingSystems,
            List<String> usualLoginMethods,
            EvidenceGrade evidenceGrade,
            List<String> evidenceCauses) {
        this(state, learnedUpdates, observations, daysCovered, windowDays, windowBasis, usualHours, seenHours, usualDays,
                seenDays, usualTargets, actionCounts, readWriteExportRatio, exportSize, resourceClasses,
                requestsPerActiveHour, usualSessionMinutes, privilegedActions, knownRareTasks, usualNetworks,
                usualDevices, usualBrowsers, usualOperatingSystems, usualLoginMethods, evidenceGrade, evidenceCauses,
                Counts.NONE);
    }

    public BaselineView {
        usualHours = immutable(usualHours);
        seenHours = immutable(seenHours);
        usualDays = immutable(usualDays);
        seenDays = immutable(seenDays);
        usualTargets = immutable(usualTargets);
        actionCounts = actionCounts == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(actionCounts));
        resourceClasses = immutable(resourceClasses);
        knownRareTasks = immutable(knownRareTasks);
        usualNetworks = immutable(usualNetworks);
        usualDevices = immutable(usualDevices);
        usualBrowsers = immutable(usualBrowsers);
        usualOperatingSystems = immutable(usualOperatingSystems);
        usualLoginMethods = immutable(usualLoginMethods);
        evidenceCauses = immutable(evidenceCauses);
        counts = counts == null ? Counts.NONE : counts;
    }

    /**
     * The view with the long-term personal baseline's state; the network, device and login dimensions stay the view's
     * own, read from the observations without the activity period being judged (W5-9).
     */
    public BaselineView withPersonalBaselineState(State baselineState, Long baselineUpdates) {
        return withPersonalBaseline(baselineState, baselineUpdates, usualNetworks, usualDevices, usualBrowsers,
                usualOperatingSystems, usualLoginMethods);
    }

    /** The view with the long-term personal baseline's state and its network, device and login dimensions. */
    public BaselineView withPersonalBaseline(
            State baselineState,
            Long baselineUpdates,
            List<String> networks,
            List<String> devices,
            List<String> browsers,
            List<String> operatingSystems,
            List<String> loginMethods) {
        return new BaselineView(baselineState, baselineUpdates, observations, daysCovered, windowDays, windowBasis,
                usualHours, seenHours, usualDays, seenDays, usualTargets, actionCounts, readWriteExportRatio, exportSize,
                resourceClasses, requestsPerActiveHour, usualSessionMinutes, privilegedActions, knownRareTasks,
                networks, devices, browsers, operatingSystems, loginMethods, evidenceGrade, evidenceCauses, counts);
    }

    /** The view with how the request's own values were seen (W5-10 D1~D3). */
    public BaselineView withRequestSeen(Map<String, Seen> request) {
        return new BaselineView(state, learnedUpdates, observations, daysCovered, windowDays, windowBasis,
                usualHours, seenHours, usualDays, seenDays, usualTargets, actionCounts, readWriteExportRatio, exportSize,
                resourceClasses, requestsPerActiveHour, usualSessionMinutes, privilegedActions, knownRareTasks,
                usualNetworks, usualDevices, usualBrowsers, usualOperatingSystems, usualLoginMethods, evidenceGrade,
                evidenceCauses, new Counts(counts.hours(), counts.days(), counts.targets(),
                counts.busiestActiveHourRequests(), counts.dayObservations(), counts.networks(), counts.devices(),
                counts.logins(), counts.identityObservations(), counts.vocabularyNotComparable(), request,
                counts.rate()));
    }

    /** The view with more causes; a STRONG grade becomes LIMITED, since a cause is a reason for caution. */
    public BaselineView withAdditionalCauses(List<String> causes) {
        if (causes == null || causes.isEmpty()) {
            return this;
        }
        List<String> merged = new ArrayList<>(evidenceCauses);
        merged.addAll(causes);
        return new BaselineView(state, learnedUpdates, observations, daysCovered, windowDays, windowBasis,
                usualHours, seenHours, usualDays, seenDays, usualTargets, actionCounts, readWriteExportRatio, exportSize,
                resourceClasses, requestsPerActiveHour, usualSessionMinutes, privilegedActions, knownRareTasks,
                usualNetworks, usualDevices, usualBrowsers, usualOperatingSystems, usualLoginMethods,
                evidenceGrade == EvidenceGrade.STRONG ? EvidenceGrade.LIMITED : evidenceGrade, merged, counts);
    }

    /** Whether the window holds any observation. */
    public boolean observed() {
        return observations > 0;
    }

    /** The work profile evidence state the v19 prompt names: TRUSTED only for STRONG evidence. */
    public String workProfileEvidenceState() {
        return evidenceGrade == EvidenceGrade.STRONG ? "TRUSTED" : "PROVISIONAL";
    }

    /** The grade with its causes: {@code LIMITED: action family inferred from protectableMethod in 25 of 25 observations}. */
    public String evidenceSummary() {
        return evidenceCauses.isEmpty() ? evidenceGrade.name() : evidenceGrade.name() + ": " + String.join("; ", evidenceCauses);
    }

    private static <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
