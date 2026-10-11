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
     */
    public record Counts(
            Map<Integer, Integer> hours,
            Map<Integer, Integer> days,
            Map<String, Integer> targets,
            int busiestActiveHourRequests,
            int dayObservations) {

        public static final Counts NONE = new Counts(Map.of(), Map.of(), Map.of(), 0, 0);

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
        }
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
