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
package io.contexa.contexaiam.admin.promptquality.screen;

import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.List;

/**
 * What the screen of measure and compare (quality plan 3.3, 3.8) reads and sends: its views (the list and the start of
 * the measurements, the result of one measurement, the comparison of two versions, the trial of the version screens
 * on the latest sealed decisions), the measurements in one list, a measurement's metrics on both bases and by resource
 * class (quality P46), and the comparison the quality gate reads, metric by metric, grade by grade and case by case.
 */
public final class PromptQualityMeasureViews {

    private PromptQualityMeasureViews() {
    }

    /**
     * A view of the screen, drawn as one tab of its tab bar (PromptQualityMeasureScreen.VIEWS is the one place that
     * lists them): a view added there is one more tab on every page of the screen, its script loaded with the screen's.
     *
     * @param key    the name of the view ({@code runs}, {@code run}, {@code compare}, ...), the page's data-view
     * @param path   the address the tab opens, under the screen's own, with its query when it has one
     *               ({@code /run?view=causes})
     * @param label  the message key of the tab's name
     * @param count  what the count beside the name counts, as the menu bar counts it, or null for none
     * @param also   the other views the tab stays lit for, such as the result of a trial under "two versions"
     * @param script the script that draws the view when it is not the screen's own, or null
     */
    public record View(String key, String path, String label, @Nullable PromptQualityScreens.Count count,
                       List<String> also, @Nullable String script) {

        public View {
            also = also != null ? List.copyOf(also) : List.of();
        }

        /** Whether the tab is lit on the view of the page. */
        public boolean lit(@Nullable String view) {
            return key.equals(view) || also.contains(view);
        }
    }

    /**
     * A tab of the views as the page draws it.
     *
     * @param href the address it opens, with the scope of the page
     * @param text its name, with the count beside it
     */
    public record Tab(String key, String href, String text, boolean selected) {
    }

    /**
     * The list and the start of the measurements.
     *
     * @param measurable whether this application can replay decisions to measure with
     */
    public record RunsView(String scope, boolean measurable, Band band, Start start,
                           List<Running> running, List<RunRow> rows, int page, int size, long total) {
    }

    /**
     * The model setting decisions are measured under now.
     *
     * @param model         the first layer's model
     * @param secondModel   the second layer's model
     * @param minimumAction the mode of the minimum action, or null when not set
     * @param settingsHash  the hash of the settings that change an answer
     */
    public record Band(@Nullable String model, @Nullable String secondModel, @Nullable String minimumAction,
                       @Nullable String settingsHash, int concurrency, int callLimit) {
    }

    /**
     * What a measurement can start with.
     *
     * @param used     the version decisions run now
     * @param repeats  the runs a measurement may take
     * @param estimate what the default choice would take, or null when nothing can be measured
     */
    public record Start(List<VersionOption> versions, @Nullable String used, List<SetOption> caseSets,
                        List<Integer> repeats, int defaultRepeats, List<Integer> sealedCounts,
                        @Nullable EstimateView estimate) {
    }

    /** @param state USED, CANARY, SHADOW, UNUSED or HIDDEN, as the version list names it */
    public record VersionOption(int number, String name, String state) {
    }

    /** A published bundle of cases a measurement can run on. */
    public record SetOption(long id, String version, String name, int cases, Instant publishedAt) {
    }

    /**
     * What a measurement would take before it starts.
     *
     * @param minutes about how long it takes, at the measured time of an answer and the replays run at once
     * @param refusal why it cannot start, or null when it can
     */
    public record EstimateView(int cases, int repeats, int answers, int reusable, int replays, int minimumCalls,
                               int maximumCalls, int callLimit, boolean withinLimit, int minutes,
                               @Nullable String refusal) {
    }

    /** A measurement that waits or runs, with its progress and about how long it has left. */
    public record Running(long id, String version, String caseSetVersion, int repeats, String status, int answered,
                          int planned, @Nullable Instant startedAt, int minutesLeft, String by) {
    }

    /**
     * A measurement of the list: on the labelled cases (CASES) or on the latest sealed decisions (SEALED, a trial).
     *
     * @param status     QUEUED, RUNNING, DONE, FAILED or CANCELLED
     * @param progress   the share of the answers taken while it runs
     * @param incomplete the answers a finished measurement could not take
     * @param miss       the miss rate on the first answer of a finished measurement on cases
     * @param falseStop  the false stop rate of the same
     * @param reference  the version a trial compared with
     * @param pairs      the decisions both versions of a trial answered
     * @param same       how many of them kept their action
     * @param anew       whether a measurement on cases was taken anew, with no kept answer used again (quality P32):
     *                   two such measurements of one version give the quality gate its noise
     */
    public record RunRow(String kind, long id, String version, @Nullable String model, String status,
                         Instant startedAt, String by, @Nullable String caseSetVersion, @Nullable Integer repeats,
                         @Nullable Double progress, int incomplete, @Nullable Rate miss, @Nullable Rate falseStop,
                         @Nullable String reference, @Nullable Integer requested, @Nullable Integer pairs,
                         @Nullable Integer same, @Nullable Long formatErrors, boolean anew) {
    }

    /**
     * A rate: its events over its trials, and its 95% interval over the distinct roots.
     *
     * @param value null when there is no trial
     */
    public record Rate(long k, long n, @Nullable Double value, @Nullable Double lo, @Nullable Double hi, int roots) {
    }

    /**
     * The result of one measurement on the labelled cases.
     *
     * @param picks            the finished measurements to choose from, newest first
     * @param missingCases     the cases of its bundle that cannot be read any more, and so are not scored
     * @param versionCreatedAt when the version was made: the cases added after it are cases its author could not see
     */
    public record RunView(long id, String version, int versionNumber, String caseSetVersion, int repeats,
                          @Nullable String model, String status, Instant createdAt, String by, int answers,
                          int incomplete, List<String> missingCases, @Nullable Instant versionCreatedAt,
                          List<Pick> picks, Basis firstAnswer, Basis finalAction) {
    }

    /** A measurement to choose from. */
    public record Pick(long id, String version, String caseSetVersion, int repeats, Instant createdAt) {
    }

    /**
     * The metrics of a measurement on one basis (the first answer, which the gate reads, or the final action).
     *
     * @param headline the miss rate, the false stop rate, the action hit rate and the citation accuracy over every case
     * @param grades   the eleven metrics over every case (ALL), then over the cases of each resource class
     */
    public record Basis(List<Metric> headline, List<GradeMetrics> grades, Split split, Later later) {
    }

    /**
     * The metrics over the cases of one resource class, or of all (ALL).
     *
     * @param metrics null when no case asks for a resource of the class
     */
    public record GradeMetrics(String key, int cases, int roots, int answers, @Nullable List<Metric> metrics) {
    }

    /**
     * A metric: a rate with its counts and 95% interval over its roots, or the decision time and answer tokens.
     *
     * @param none      why there is no value: ONE_RUN (consistency needs two runs or more) or NO_CASES
     * @param median    the median decision time in milliseconds (the time row only)
     * @param anyCases  quality plan 3.3: the cases where it happened in at least one run, shown beside the rate only;
     *                  null with one run, for the consistency and the time row, which it does not apply to
     * @param anyOf     the cases with a trial that {@code anyCases} is out of; null when {@code anyCases} is
     */
    public record Metric(String key, @Nullable Long k, @Nullable Long n, @Nullable Double value, @Nullable Double lo,
                         @Nullable Double hi, int roots, @Nullable String none, @Nullable Double median,
                         @Nullable Double p95, @Nullable Double tokens, @Nullable Double tokensP95,
                         @Nullable Integer anyCases, @Nullable Integer anyOf) {
    }

    /** Plan 9: the default bundle and our cases seen apart, by their misses. */
    public record Split(Part contexa, Part ours) {
    }

    public record Part(int cases, Metric miss) {
    }

    /**
     * Quality plan 3.2: the cases added after the version was made, which its author could not see.
     *
     * @param worse the misses there are worse than over every case beyond their 95% interval
     */
    public record Later(int cases, Metric miss, Metric overall, boolean worse) {
    }

    /**
     * Two versions compared as the quality gate compares them: the candidate and the version in use, measured the same
     * way on the latest published bundle.
     *
     * @param versions         the versions to choose from
     * @param picks            the finished measurements to choose from, for two measurements
     * @param candidateMeasure the measurement compared, when two measurements were asked for
     * @param referenceMeasure the measurement it is compared with, when two measurements were asked for
     * @param state            the state of the measurements, as the gate reads them (MEASURED, MISSING, STALE, ...),
     *                         NONE with no candidate, NOT_FOUND or INCOMPARABLE for two measurements asked for
     * @param sides            the sides the state is about
     * @param detail           why, in a code; null when there is nothing to add
     * @param differences      why two measurements cannot be compared: CASE_SET, MODEL_SETTING, REPEATS
     * @param comparable       whether the two were measured the same way, so they are compared
     * @param noise            the width within which a rate counts as the same, by metric; empty when it is not known
     */
    public record CompareView(String scope, List<VersionOption> versions, List<Pick> picks,
                              @Nullable Integer candidate, @Nullable Integer current, @Nullable Long candidateMeasure,
                              @Nullable Long referenceMeasure, String state, List<String> sides,
                              @Nullable String detail, List<String> differences, @Nullable Side currentSide,
                              @Nullable Side candidateSide,
                              @Nullable Same same, boolean comparable, List<MetricCompare> metrics,
                              @Nullable TimeCompare time, Splits splits, List<GradeCompare> grades,
                              List<SplitRow> rows, List<Noise> noise) {
    }

    /**
     * A side of the comparison: its version and the measurement read for it.
     *
     * @param measureId the measurement, or null for a measurement the product shipped
     */
    public record Side(String version, @Nullable Long measureId) {
    }

    /** What the two measurements share: the bundle, the model setting and the runs. */
    public record Same(String caseSetVersion, String model, int repeats) {
    }

    /**
     * A metric of the two versions over the cases both answered.
     *
     * @param verdict BETTER, SAME, WORSE or UNDECIDABLE
     */
    public record MetricCompare(String key, String verdict, @Nullable Double currentValue,
                                @Nullable Double candidateValue, @Nullable Rate current, @Nullable Rate candidate) {
    }

    /** The decision time and answer tokens of the two versions, their medians; no verdict is computed for them. */
    public record TimeCompare(@Nullable Double currentMedian, @Nullable Double candidateMedian,
                              @Nullable Double currentTokens, @Nullable Double candidateTokens) {
    }

    /** The cases the two versions answer differently, by how. */
    public record Splits(int newMiss, int newCatch, int newStop, int newPass) {
    }

    /**
     * The misses of one resource class.
     *
     * @param compared whether a case asks for a resource of the class
     * @param verdict  the paired comparison of the misses of the class, or null when not compared
     */
    public record GradeCompare(String key, int cases, boolean compared, int changed, int newMisses,
                               @Nullable String verdict, @Nullable Rate current, @Nullable Rate candidate) {
    }

    /**
     * A case the two versions answer differently.
     *
     * @param split NEW_MISS, NEW_CATCH, NEW_STOP or NEW_PASS
     */
    public record SplitRow(String key, String name, String split, List<String> currentActions,
                           List<String> candidateActions) {
    }

    public record Noise(String key, double width) {
    }

    /** One case's answers of the two versions side by side. */
    public record CaseAnswers(String key, String name, AnswerSide current, AnswerSide candidate) {
    }

    /**
     * The answers of one version to the case.
     *
     * @param actions      the first answer of each run, null for a run not taken
     * @param finalActions the final action of each run
     * @param findings     the reason codes the first run cited, each with the fact it cites and what it came to
     */
    public record AnswerSide(String version, @Nullable Long measureId, List<String> actions, List<String> finalActions,
                             List<Finding> findings) {
    }

    /** @param outcome MATCH, MISMATCH or UNDECIDED */
    public record Finding(@Nullable String code, @Nullable String fact, @Nullable String outcome) {
    }

    /** A measurement started: its id. */
    public record Started(long id) {
    }

    public record Cancelled(boolean cancelled) {
    }

    /** A request the screen refuses: 422 with the code the screen names. */
    public record Refused(String code) {
    }
}
