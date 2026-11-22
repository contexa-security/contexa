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
package io.contexa.contexaiam.admin.promptquality.report;

import io.contexa.contexacore.std.components.prompt.quality.QualityCaseChanges;
import io.contexa.contexaiam.admin.promptquality.status.PromptQualityStatus;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionChange;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Map;

/**
 * The quality report (quality plan 3.7): the measurements of the versions, the case set versions they ran on, the
 * operation metrics, the overturned decisions and the changes and approvals of a scope over a period, in one bundle.
 * It is what the bundle's machine-readable file holds, field by field; the readable files are drawn from it.
 *
 * <p>Three questions of the regulations are answered in their own sections: the declaration of the accuracy metrics
 * ({@link #accuracy}), the monitoring after the release ({@link #monitoring}) and the monitoring of the decisions people
 * overturned ({@link #reversals}). A number is given with its numerator, its denominator and its 95% interval; a
 * section without data says why ({@code missing}) instead of giving zeros. Every value is masked before it is kept
 * here ({@link #masking}): no case input, request or baseline is in it, a person a decision was about is named by a
 * pseudonym of this report alone, and the free texts are scrubbed.</p>
 *
 * @param format the name and version of this format
 */
public record QualityReport(String format, Header header, Accuracy accuracy, CaseSets caseSets,
                            Monitoring monitoring, Reversals reversals, History history, Masking masking) {

    /** The name and version of the format; a reader that does not know the version does not read on. */
    public static final String FORMAT = "contexa-prompt-quality-report/1";

    /** The section that answers the declaration of the accuracy metrics (EU AI Act, article 15). */
    public static final String ACCURACY_DECLARATION = "accuracy";
    /** The section that answers the monitoring after the release (EU AI Act, article 72). */
    public static final String POST_MARKET_MONITORING = "monitoring";
    /** The section that answers the monitoring of the decisions people overturned (NIST AI RMF, MANAGE). */
    public static final String OVERTURNED_DECISIONS = "reversals";

    /**
     * What the report is of.
     *
     * @param decisionTenant the tenant whose decisions the operation metrics, the reversals and the causes of rated
     *                       decisions are read for; null for every tenant (the platform scope)
     * @param answers        each question of the regulations and the section that answers it
     * @param gate           the quality gate of the installation: its mode and its thresholds
     * @param modelSetting   the server settings that change an answer, as this server runs them; null when this
     *                       application cannot measure
     */
    public record Header(String generatedAt, String exportedBy, String scope, String prompt, String from, String to,
                         @Nullable String decisionTenant, Map<String, String> answers, Gate gate,
                         @Nullable ModelSetting modelSetting, boolean measurable, boolean operationsReadable) {
    }

    /** The quality gate as the installation applies it (plan 3.4). */
    public record Gate(String mode, double modelLessLimit, double significance, int minimumStopRoots,
                       int minimumAllowRoots) {
    }

    /** The server settings that change an answer (plan 3.3) and their hash, the fingerprint of the measurements. */
    public record ModelSetting(String settingsHash, Map<String, String> settings) {
    }

    // ----- 1. the declaration of the accuracy metrics -----

    /**
     * The version that decides now and how well it decides on the labelled cases.
     *
     * @param missing      why there is nothing to declare: {@code NO_VERSION_IN_USE}, {@code UNMEASURABLE},
     *                     {@code NO_CASE_SET} or {@code NO_MEASUREMENT}; null when it is declared
     * @param state        the state of its measurement ({@code MEASURED}, {@code STALE}, {@code MISSING},
     *                     {@code BASELINE_PENDING} or {@code UNMEASURABLE})
     * @param declared     its latest measurement, on both bases
     * @param sufficiency  whether its cases are enough to tell versions apart
     * @param alone        the conditions of the gate one measurement decides by itself
     * @param comparisons  the paired comparison of the version in use with each version that decided before it
     * @param measurements the measurements of the prompt in the scope finished in the period, the newest first
     * @param measurementsLeftOut how many more finished in the period than are listed
     */
    public record Accuracy(@Nullable String missing, @Nullable String version, @Nullable String versionSource,
                           String state, boolean measuring, @Nullable VersionInfo versionInfo,
                           @Nullable Declared declared, @Nullable Sufficiency sufficiency, List<Finding> alone,
                           List<Comparison> comparisons, List<MeasurementRow> measurements, int measurementsLeftOut) {
    }

    /** A version as it was registered; its title is scrubbed. */
    public record VersionInfo(String name, int number, String provider, String origin, String createdBy,
                              String createdAt, String contentHash, @Nullable String title) {
    }

    /**
     * A measurement of the version in use, with every rate on the first answer (the prompt's quality, which the gate
     * reads) and on the final action (what the user meets).
     *
     * @param fresh               whether it ran under the settings this server runs
     * @param changedSettings     the settings that differ from this server's, each before and now
     * @param secondAnalysisCases how many cases of its set were promoted from a decision the second analysis decided
     * @param secondAnalysisFirstAnswer their first-answer rates, counted apart; null without such cases
     * @param missingCases        the cases of its set that cannot be read any more, and so are not scored
     */
    public record Declared(long measureId, String version, String caseSetVersion, int repeats, String modelSetting,
                           @Nullable String startReason, @Nullable String finishedAt, boolean fresh,
                           Map<String, List<String>> changedSettings, PromptQualityStatus.Score firstAnswer,
                           PromptQualityStatus.Score finalAction, int secondAnalysisCases,
                           @Nullable PromptQualityStatus.Score secondAnalysisFirstAnswer, List<String> missingCases) {
    }

    /**
     * Whether the cases are enough to tell two versions apart (plan 3.2): the distinct roots of the cases that must be
     * stopped and of those that must be allowed, against the numbers the gate needs. Below them a comparison is
     * undecidable, whatever its rates say.
     */
    public record Sufficiency(int stopRoots, int neededStopRoots, int allowRoots, int neededAllowRoots,
                              boolean enough) {
    }

    /** One condition of the gate (plan 3.4): its result, the numbers it rests on and the cases it names. */
    public record Finding(String condition, String status, Map<String, Number> figures, List<String> caseKeys) {
    }

    /**
     * The version in use compared with one version before it, as the gate compares a candidate with the version in
     * use: on the same case set version, model setting and runs.
     *
     * @param against  the version before
     * @param state    the state of the measurements of the two ({@code MEASURED}, {@code STALE}, ...)
     * @param verdict  the verdict of the conditions as computed
     * @param metrics  the paired comparison of every rate; empty when the two could not be compared
     * @param changes  the cases the two versions answer differently
     */
    public record Comparison(String against, String state, List<String> sides, @Nullable String detail,
                             String verdict, List<MetricComparison> metrics, List<Finding> findings,
                             QualityCaseChanges changes) {
    }

    /**
     * The paired comparison of one rate (plan 3.3): better, the same, worse or undecidable, with the numbers behind it.
     * A value that could not be taken is null.
     */
    public record MetricComparison(String metric, String verdict, @Nullable Double inUseValue,
                                   @Nullable Double beforeValue, @Nullable Double difference,
                                   @Nullable Double noiseWidth, int pairedCases, int pairedRoots, int worseRoots,
                                   int betterRoots, @Nullable Double worseProbability,
                                   @Nullable Double betterProbability) {
    }

    /**
     * A measurement finished in the period; its rates are given when it is done.
     *
     * @param failure why it did not finish, scrubbed; null when it did
     */
    public record MeasurementRow(long id, String version, String caseSetVersion, int repeats, String modelSetting,
                                 String status, @Nullable String startReason, String createdBy,
                                 @Nullable String finishedAt, int answered, @Nullable String failure,
                                 @Nullable PromptQualityStatus.Score firstAnswer,
                                 @Nullable PromptQualityStatus.Score finalAction) {
    }

    // ----- 2. the case set versions -----

    /**
     * The labelled cases of the scope and the published set versions the measurements ran on.
     *
     * @param missing why there is no published set: {@code NO_CASE_SET}; null when there is one
     * @param sets    the latest set, those published in the period and those the listed measurements ran on
     */
    public record CaseSets(@Nullable String missing, Inventory inventory, List<SetRow> sets) {
    }

    /**
     * The cases kept in the scope now, counted by where they came from (plan 3.2, 3.6).
     *
     * @param kept           the cases kept in the scope
     * @param operation      those promoted from a decision of the operation
     * @param secondAnalysis those promoted from a decision the second analysis decided
     * @param pending        those whose answer waits for another administrator
     */
    public record Inventory(int kept, int operation, int secondAnalysis, int pending, boolean twoPersonConfirmation,
                            String defaultSetVersion, int defaultSetCases) {
    }

    /**
     * A published set version and what it holds.
     *
     * @param reasons     why it is listed: {@code LATEST}, {@code PUBLISHED_IN_PERIOD}, {@code MEASURED}
     * @param readable    the cases of it that can be read now
     * @param missingCases the cases of it that cannot be read any more (deleted, or changed by an upgrade)
     * @param byOrigin    the readable cases by where they came from
     * @param byGrade     by their grade
     * @param byClass     by the class of their answer
     * @param byKind      by who is behind the request
     * @param stopRoots   the distinct roots of the cases that must be stopped
     * @param allowRoots  the distinct roots of the cases that must be allowed
     * @param secondAnalysis the readable cases promoted from a decision the second analysis decided
     */
    public record SetRow(long id, String version, String name, int caseCount, @Nullable String defaultSetVersion,
                         int defaultCaseCount, String publishedBy, String publishedAt, List<String> reasons,
                         int readable, List<String> missingCases, Map<String, Integer> byOrigin,
                         Map<String, Integer> byGrade, Map<String, Integer> byClass, Map<String, Integer> byKind,
                         int stopRoots, int allowRoots, int secondAnalysis) {
    }

    // ----- 3. the monitoring after the release -----

    /**
     * How the versions decided in operation over the period, the version change, the measurements taken again and what
     * there is to check.
     *
     * @param missing        why there are no operation metrics: {@code NO_OPERATIONS} (no Zero Trust console in this
     *                       application) or {@code NO_DECISIONS_IN_PERIOD}; null when there are
     * @param versions       the six operation metrics of each version that decided in the period
     * @param change         the version in use beside the version it replaced, over two periods of the same length
     * @param latestRemeasure the latest comparison of the version in use measured again with its measurement before
     * @param nextScheduled  when the version in use is measured again next on schedule; null when it is off
     * @param toCheck        what the state of quality says there is to check, worst first
     * @param measurementCauses the causes of the wrong answers of the declared measurement
     * @param decisionCauses the causes of the decisions rated inadequate in the period
     */
    public record Monitoring(@Nullable String missing, List<VersionOperation> versions,
                             @Nullable VersionChange change, @Nullable Remeasure latestRemeasure,
                             @Nullable String nextScheduled, List<PromptQualityStatus.ToCheck> toCheck,
                             long pendingReviews, Causes measurementCauses, Causes decisionCauses) {
    }

    /**
     * The operation metrics of one version over the period (plan 3.6): the share of decisions that stopped the
     * request, of challenges passed, of blocks released, of reviewed decisions found valid, of decisions asked again
     * and of decisions set without the model, each with its 95% interval over the decisions.
     */
    public record VersionOperation(String version, boolean inUse, @Nullable String firstHour,
                                   @Nullable String lastHour, long decisions, Map<String, PromptQualityStatus.Rate> rates) {
    }

    /** A measurement of the version in use taken again and compared with the one before it (plan 3.6). */
    public record Remeasure(long measureId, @Nullable Long comparedMeasureId, String verdict,
                            @Nullable String startReason, String comparedAt, Map<String, Object> detail) {
    }

    /**
     * The causes of wrong answers (plan 3.5), counted by cause.
     *
     * @param missing       why there are none: {@code NO_CAUSES} (this application does not classify),
     *                      {@code NO_MEASUREMENT}; null when there are
     * @param withoutRecord the decisions rated inadequate whose decision record is gone
     */
    public record Causes(@Nullable String missing, @Nullable Long measureId, List<CauseCount> counts, int listed,
                         int withoutRecord) {
    }

    /** How many wrong answers one cause has, where it is fixed, and for how many its rule could not be computed. */
    public record CauseCount(String cause, @Nullable String fix, int count, int notComputed) {
    }

    // ----- 4. the decisions people overturned -----

    /**
     * The decisions people overturned in the period (by when they overturned them): a block an administrator released,
     * a decision an administrator rated wrong (the latest rating counts), and an allowed request found to be a breach.
     *
     * @param missing      why there are none: {@code NO_REVERSALS_IN_PERIOD}; null when there are
     * @param kinds        each kind with its decisions, by the decision's own action, version and the reason given
     * @param invalidShare of the decisions whose latest rating fell in the period, those rated wrong
     * @param entries      the overturned decisions, the latest first
     * @param leftOut      how many more there are than are listed
     */
    public record Reversals(@Nullable String missing, List<KindSummary> kinds, PromptQualityStatus.Rate invalidShare,
                            List<ReversedDecision> entries, int leftOut) {
    }

    /** One kind of overturning: how many decisions, by their own final action, version and the rating's reason. */
    public record KindSummary(String kind, int decisions, Map<String, Integer> byAction, Map<String, Integer> byVersion,
                              Map<String, Integer> byReason) {
    }

    /**
     * One overturned decision. The person it was about is a pseudonym of this report. The note an administrator wrote
     * on it is left out: it describes the person's request (a device, a place, a colleague) in words no rule can be
     * sure to find, and the reason code says what was wrong.
     *
     * @param recordFound whether the decision's own record is still there to read its action and version from
     * @param noted       whether the administrator wrote a note, which the report leaves out
     */
    public record ReversedDecision(String occurredAt, String kind, @Nullable String observationId,
                                   boolean recordFound, @Nullable String decidedAt, @Nullable String action,
                                   @Nullable String proposedAction, @Nullable String version,
                                   @Nullable String evaluationReason, @Nullable String reviewer, boolean noted,
                                   @Nullable String subject) {
    }

    // ----- 5. the changes and approvals -----

    /**
     * What was done to the versions, the cases and the sets in the period (plan 3.4, 3.9): the audit log, the
     * transitions of the release workflow with their gate state, and the rollbacks executed.
     *
     * @param auditByAction how many audit records of each action
     * @param overrides     the transitions that overrode the quality gate
     */
    public record History(List<AuditEntry> audit, int auditLeftOut, Map<String, Integer> auditByAction,
                          List<Transition> transitions, int transitionsLeftOut, int overrides,
                          List<Rollback> rollbacks, int rollbacksLeftOut) {
    }

    /** One record of the audit log; its reason is scrubbed. */
    public record AuditEntry(String at, String actor, String action, String resource, @Nullable String reason) {
    }

    /** One transition of the release workflow; its rationale and blockers are scrubbed. */
    public record Transition(String at, String version, String fromStatus, String toStatus, String workflowState,
                             String gateState, boolean overridden, String channel, String actor, String rationale,
                             @Nullable String blockers) {
    }

    /** One rollback executed; its reason is scrubbed. */
    public record Rollback(String executionKey, String at, String fromVersion, String toVersion,
                           @Nullable String actor, @Nullable String reason, boolean emergency, String status,
                           @Nullable String approvedBy, @Nullable String approvedAt) {
    }

    // ----- 6. the masking -----

    /**
     * How the report was masked (plan 3.2).
     *
     * @param rules          the rules applied
     * @param subjects       the distinct people named by a pseudonym
     * @param scrubbedTexts  the free texts in which something was replaced
     */
    public record Masking(List<String> rules, int subjects, int scrubbedTexts) {
    }
}
