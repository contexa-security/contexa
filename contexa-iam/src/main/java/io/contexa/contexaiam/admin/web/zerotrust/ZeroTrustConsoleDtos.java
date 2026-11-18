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
package io.contexa.contexaiam.admin.web.zerotrust;


import java.util.List;
import java.util.Map;

/**
 * What the Zero Trust console's screens receive (console design 6). Every number is a {@link MetricValue}: its name,
 * its definition, its value and, for a ratio, its numerator and denominator, or the reason it has no value.
 */
public final class ZeroTrustConsoleDtos {

    private ZeroTrustConsoleDtos() {
    }

    /**
     * A number with its definition (console design 2): its name and what it counts, its value, its numerator and
     * denominator for a ratio, its unit, and the reason it has none when no value can be given.
     */
    public record MetricValue(String key, String label, String description, Double value, Long numerator,
                              Long denominator, String unit, String noDataReason) {
    }

    /** The period a screen reads: its key (day, week, month, quarter, custom) and its bounds. */
    public record Period(String key, String from, String to) {
    }

    /** The band above every screen (console design 6.0). */
    public record Header(Period period, String mode, String modeSince, long decisions, long users,
                         List<Share> bundles, List<Share> models, boolean standalone, String tenant) {
    }

    /** A ratio with its 95% range (Wilson) and the sample it was read from. */
    public record RangedMetric(MetricValue metric, Double lower95, Double upper95, long sample) {
    }

    /** A part of a whole: its key, its count and its share of the whole (null when the whole is empty). */
    public record Share(String key, long count, Double ratio) {
    }

    /**
     * One day of the decision trend: the decisions by action, the technical failures, the share with an established
     * baseline, who set the action, the step-ups passed, the tokens, the coverage counts (null when a tenant is
     * chosen), the 95th percentile of the decision time and the decisions of protected calls (the coverage's part).
     */
    public record DayPoint(String day, long allow, long challenge, long escalate, long block, long noDecision,
                           Double baselineEstablished, long model, long engineChanged, long modelLess, long passed,
                           long tokens, Long protectedCalls, Long reused, Long totalP95Ms, long protectedDecisions,
                           Long skipped) {
    }

    /** One cell of a matrix: its row, its column and its count. */
    public record Cell(String row, String column, long count) {
    }

    /** One hour of the throughput. */
    public record HourPoint(String hour, long decisions, Long protectedCalls) {
    }

    /** One component a decision passes through, its state (GOOD, WARN, BAD, UNKNOWN) and what it says. */
    public record Component(String key, String status, String value, String noDataReason) {
    }

    /** A rule-made warning of the overview: its key, its severity, its sentence and the decision list it opens. */
    public record Alert(String key, String severity, String message, String link) {
    }

    /** A ranked item: a user, a resource, a reason or a fact, and what it counts. */
    public record RankedItem(String item, long count, Map<String, Long> byDetail, String note) {
    }

    // ----- overview (6.1) -----

    public record Overview(Header header, OverviewSummary summary, CoverageCard coverage, StoppedCard stopped,
                           ImpactCard impact, TrustCard trust, List<DayPoint> trend, List<Share> stopReasonGroups,
                           List<Alert> alerts, Previous previous) {
    }

    /**
     * Design 6.1: the key numbers of the period of the same length before this one, for the change beside each; a
     * number without a denominator in that period is null.
     */
    public record Previous(Period period, Double coverage, Double stopped, Double challengePass, Double modelDecided) {
    }

    /** The numbers the overview's sentence is made of. */
    public record OverviewSummary(long decisions, long stopped, Double stoppedRatio, long challenges,
                                  long challengesPassed, long blocks, long blocksReleased) {
    }

    public record CoverageCard(MetricValue coverage, MetricValue noDecision, List<Share> noDecisionReasons) {
    }

    public record StoppedCard(MetricValue stopped, List<Share> byAction, MetricValue beforeResponse) {
    }

    public record ImpactCard(MetricValue challengesPerUserWeek, RangedMetric challengePass, MetricValue userWaitP95,
                             RangedMetric blockRelease) {
    }

    public record TrustCard(MetricValue modelDecided, MetricValue baselineEstablished, RangedMetric reviewValid,
                            MetricValue modelLess) {
    }

    // ----- threats and business impact (6.2) -----

    /**
     * @param whenStopped       the stopped decisions by weekday (1 Monday to 7 Sunday) and four-hour band (0 to 5)
     * @param hypothesisByClass the stopped decisions by most likely explanation and resource class
     * @param burdenHistogram   the decided users by the step-ups they got in the period: 0, 1, 2, 3, 4 or more
     */
    public record Impact(Header header, StoppedSide stopped, CostSide cost, List<Cell> whenStopped,
                         List<Cell> hypothesisByClass, List<Share> burdenHistogram) {
    }

    public record StoppedSide(long stopped, List<Share> byAction, List<Share> timing, long explained,
                              List<Share> hypotheses, List<Share> resourceClasses, List<RankedItem> topReasons,
                              List<RankedItem> topResources, List<RankedItem> topUsers, long reasoned) {
    }

    public record CostSide(ChallengeFunnel challenges, MetricValue userWaitP50, MetricValue userWaitP95,
                           long escalations, BlockOutcome blocks, MetricValue burdenMedianPerWeek,
                           MetricValue burdenP95PerWeek, List<ChallengedUser> topChallengedUsers) {
    }

    public record ChallengeFunnel(long required, MetricValue codeRequests, long passed, long failed, long expired,
                                  RangedMetric passRate) {
    }

    /**
     * The blocks with what came of them; the release median is the release time bucket it falls in (unit
     * {@code RELEASE_BUCKET}, the value its index, the numerator the releases it was read from).
     */
    public record BlockOutcome(long blocks, long released, long kept, MetricValue releaseMedian) {
    }

    public record ChallengedUser(String user, long challenges, long passed, String mainReason, String baseline) {
    }

    /** N17: a user's challenges of the period and the moment of the latest one (K104). */
    public record UserChallenges(String user, long challenges, String lastAt) {
    }

    // ----- trust (6.3) -----

    public record Trust(Header header, SourceSection source, EvidenceSection evidence, OutcomeSection outcomes,
                        QualitySection quality, List<BundleModelRow> changes, List<DayPoint> trend) {
    }

    public record SourceSection(MetricValue model, MetricValue engineChanged, MetricValue modelLess,
                                List<Share> engineCauses, List<Share> modelLessCauses, long modelLessBlocks) {
    }

    public record EvidenceSection(List<Share> baseline, long usersEstablished, long users, List<Share> context,
                                  List<UnknownFact> unknownFacts) {
    }

    public record UnknownFact(String fact, long decisions, String reason) {
    }

    public record OutcomeSection(RangedMetric challengePass, RangedMetric blockRelease, RangedMetric reviewValid,
                                 List<Share> invalidReasons, long reviewPending) {
    }

    public record QualitySection(MetricValue corrected, MetricValue formatFallback, MetricValue contractFallback) {
    }

    /** One prompt bundle and model, the period it decided in and how its decisions came out. */
    /**
     * Plan 3.10 (2): the decisions of one prompt version since {@code from}: how many, the median decision time, the
     * share asked again and the share of no usable answer (null without decisions), and the decisions per action.
     */
    public record VersionDecisions(String version, String from, long decisions, Long medianMs, Double retriedRatio,
                                   Double malformedRatio, Map<String, Long> actions) {
    }

    public record BundleModelRow(String bundle, String model, String from, String to, long decisions,
                                 Double stoppedRatio, Double modelLessRatio) {
    }

    // ----- decision records (6.4) -----

    public record DecisionPage(List<DecisionRow> rows, String nextCursor) {
    }

    public record DecisionRow(String observationId, String createdAt, String user, String resource, String method,
                              String resourceClass, String action, String source, String hypothesis, String firstReason,
                              String firstReasonGroup, String outcome, Long totalMs, String mode, String actor) {
    }

    public record DecisionDetail(String observationId, String requestId, String createdAt, String mode, String actor,
                                 String action, String proposedAction, String source, String cause, String timing,
                                 Long totalMs, String bundle, String model, boolean explained, String conclusion,
                                 List<ReasonView> reasons, String modelReason, List<Map<String, Object>> hypotheses,
                                 List<Map<String, Object>> deviations, Map<String, Object> unknown,
                                 String baselineStatus, String contextLevel, List<OutcomeView> outcomes,
                                 Map<String, Long> timings, Long auditId, String packageId, boolean inReview,
                                 String user, String resource, String resourceClass, String engineReason,
                                 boolean usualKept, List<Map<String, Object>> ruleBreaches, String reviewReason,
                                 boolean standalone, String stage, Integer modelCalls, Long promptTokens,
                                 Long outputTokens, Boolean retried, Long baselineLearned, Integer baselineDays,
                                 boolean learned, Integer bundleNumber) {
    }

    /**
     * A reason with the fact it cites: the fact's value as the engine gave it to the model, and in words of the
     * request's language (K122: the role scope's codes read by their words).
     */
    public record ReasonView(int rank, String code, String group, String fact, String factName, String factValue,
                             String factText) {
    }

    public record OutcomeView(String kind, String at, String actor, String note, String reason) {
    }

    /** A page of the review queue, the oldest sample day last, and the entries waiting in all. */
    public record ReviewPage(List<ReviewItem> items, String nextCursor, long pending) {
    }

    public record ReviewItem(String observationId, String sampleDay, String createdAt, String user, String resource,
                             String action, String hypothesis, String firstReason, String reason) {
    }

    /** An administrator's evaluation of a decision (console decision 11.3). */
    public record Evaluation(Boolean valid, String reason, String note) {
    }

    public record EvaluationSaved(String outcomeId, String observationId, String kind) {
    }

    // ----- adoption (6.5) -----

    /**
     * @param trend the SHADOW decisions of each day: what would have been stopped, and the share with an established
     *              baseline, from which the screen reads how the baseline grows
     */
    /** @param pastWindows the measuring windows the AI monitor's reset closed, newest first (console plan 5-2 ⑤) */
    public record Adoption(Header header, String verdict, int unmet, String observedMode, String observedSince,
                           long observedDays, List<Criterion> criteria, WouldHave wouldHave, List<DayPoint> trend,
                           List<ModeChange> modeHistory, List<PastWindow> pastWindows) {
    }

    /**
     * A measuring window the AI monitor kept when an operator restarted it: its span, its decisions, its failure and
     * timeout shares, its p95 and the readiness it found. The windows stop with the reset (console design 11.4); the ones
     * kept stay readable.
     */
    public record PastWindow(String startedAt, String endedAt, long decisions, Double failureRate, Double timeoutRate,
                             Double p95LatencyMs, String recommendation, String closedBy, String reason) {
    }

    /** One criterion: what it measures now, the recommended bound and whether it is met. */
    public record Criterion(String key, MetricValue current, String threshold, String status) {
    }

    /** What SHADOW would have stopped had it been ENFORCE. */
    public record WouldHave(long stopped, long users, long blockedAccounts, MetricValue burdenMedianPerWeek,
                            MetricValue burdenP95PerWeek) {
    }

    public record ModeChange(String at, String from, String to, String by, String reason) {
    }

    // ----- operations (6.6) -----

    /**
     * @param providers the decisions by the provider that answered, with its models (console plan 5-2 ①)
     * @param triggers  the decisions by what started their analysis: a protected method, an AuthZEN evaluation (5-2 ②)
     */
    public record Operations(Header header, List<Component> components, Throughput throughput,
                             List<HourPoint> hourly, List<Share> noDecisionReasons, List<FailureDay> failureTrend,
                             List<RankedItem> failedPaths, List<StageLatency> latency, List<Share> analysisTimeBuckets,
                             List<DayPoint> trend, Cost cost, List<BundleModelRow> usage, List<RankedItem> providers,
                             List<Share> triggers, Storage storage) {
    }

    /** The calls and decisions per minute, the analyses in line and the most the line holds (null: no bound). */
    public record Throughput(MetricValue protectedPerMinute, MetricValue decisionsPerMinute, Integer inLine,
                             Integer lineBound) {
    }

    public record FailureDay(String day, Map<String, Long> byKind) {
    }

    /** @param averageMs the stage's mean, from the summed times (console plan 5-2 ④); null when nothing was measured */
    public record StageLatency(String stage, Long p50Ms, Long p95Ms, Long averageMs, long measured) {
    }

    public record Cost(MetricValue tokensPerDecision, MetricValue callsPerDecision, MetricValue costPerDay,
                       String currency) {
    }

    /**
     * How long the rows are kept, about how many decision rows there are (the database's estimate, no count of the
     * table) and when the next retention pass runs.
     */
    public record Storage(int decisionRetentionDays, int aggregateRetentionDays, boolean standalone, Long decisionRows,
                          String nextCleanup) {
    }
}
