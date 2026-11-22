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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseChanges;
import io.contexa.contexacore.std.components.prompt.quality.QualityComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateCondition;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateEvaluator;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateFinding;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateResult;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateVerdict;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityStatistics;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.causes.PromptQualityCauses;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.QualityScheduledMeasurement;
import io.contexa.contexaiam.admin.promptquality.status.PromptQualityStatus;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.PeriodRate;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionPeriod;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * The quality report of a scope over a period (quality plan 3.7): the measurements of the version in use and of the
 * versions before it, the case set versions they ran on, the operation metrics, the decisions people overturned and
 * the changes and approvals, in one bundle ({@link QualityReportBundle}). It is the evidence an installation gives for
 * the declaration of the accuracy metrics, the monitoring after the release and the monitoring of the overturned
 * decisions, and it is masked as it is read ({@link QualityReportMasking}).
 *
 * <ul>
 * <li>The scope is that of the prompt versions ({@code registry_scope}); the decisions read with it are its tenant's,
 * and those of every tenant for the platform scope, as the trials and the causes read them.</li>
 * <li>The period is when things happened: a measurement finished, a set was published, a decision was made (the
 * operation metrics), a decision was overturned, a change was recorded. The version in use and its latest measurement
 * are those of now.</li>
 * <li>Nothing is written but the causes the classifier keeps when they are read, as the screens read them; nothing
 * asks a model.</li>
 * </ul>
 */
public class PromptQualityReports {

    private static final Logger log = LoggerFactory.getLogger(PromptQualityReports.class);

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    /** The period when none is asked for: the longest period of the console's screens. */
    static final Duration DEFAULT_PERIOD = Duration.ofDays(90);
    /** The longest period a report covers, as the console's custom period. */
    static final Duration MAX_PERIOD = Duration.ofDays(400);
    /** The most rows of one list; more are counted, not listed. */
    static final int MEASUREMENT_LIMIT = 50;
    static final int REVERSAL_LIMIT = 1000;
    static final int AUDIT_LIMIT = 2000;
    static final int TRANSITION_LIMIT = 1000;
    static final int ROLLBACK_LIMIT = 500;
    private static final DateTimeFormatter FILE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss");
    private static final List<QualityGateCondition> ALONE = List.of(QualityGateCondition.MUST_CATCH_NEVER_ALLOWED,
            QualityGateCondition.MUST_NOT_BLOCK_NEVER_BLOCKED, QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY);
    private static final String RELEASED = ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED.name();
    private static final String BREACH = ZeroTrustDecisionOutcomes.Kind.ALLOWED_BREACH_CONFIRMED.name();
    private static final String VALID = ZeroTrustDecisionOutcomes.Kind.EVALUATED_VALID.name();
    private static final String INVALID = ZeroTrustDecisionOutcomes.Kind.EVALUATED_INVALID.name();
    private static final List<String> KINDS = List.of(RELEASED, INVALID, BREACH);

    /**
     * What a report is asked for.
     *
     * @param scope      the scope of the prompt versions, or null for the platform
     * @param from       the start of the period, or null for 90 days before its end
     * @param to         the end of the period (not in it), or null for now; a later end is now
     * @param exportedBy who asks for it
     */
    public record Request(@Nullable String scope, @Nullable Instant from, @Nullable Instant to, String exportedBy) {
    }

    /** A report as its bundle: the file's name, its bytes, and the report it holds. */
    public record Export(String fileName, byte[] bytes, QualityReport report) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final PromptQualityCases cases;
    private final PromptQualityStatus status;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final Supplier<PromptQualityCauses> causes;
    private final Supplier<ZeroTrustConsoleService> console;
    private final QualityGatePolicy gate;
    private final QualityReportBundle bundle;
    private final Clock clock;
    private final SecureRandom random;

    /**
     * @param measurements the measurement runner; a supplier of null when this application cannot replay decisions
     * @param causes       the causes of the wrong answers; a supplier of null when there are none
     * @param console      the Zero Trust console's hourly table; a supplier of null when the console is not here
     * @param gate         the quality gate of the installation, with the measurements it reads
     */
    public PromptQualityReports(Supplier<JdbcTemplate> jdbc, PromptVersionService versions, PromptQualityCases cases,
                                PromptQualityStatus status, Supplier<PromptQualityMeasurements> measurements,
                                Supplier<PromptQualityCauses> causes, Supplier<ZeroTrustConsoleService> console,
                                QualityGatePolicy gate, MessageSource messages, ObjectMapper json,
                                @Nullable Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.status = Objects.requireNonNull(status, "status");
        this.measurements = measurements != null ? measurements : () -> null;
        this.causes = causes != null ? causes : () -> null;
        this.console = console != null ? console : () -> null;
        this.gate = gate != null ? gate : QualityGatePolicy.none();
        this.bundle = new QualityReportBundle(messages, json);
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.random = new SecureRandom();
    }

    /** The report as its bundle, named as the console's exports are: {@code prompt-quality-report-<time>.zip}. */
    public Export export(Request request) {
        QualityReport report = report(request);
        String fileName = "prompt-quality-report-" + LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC)
                .format(FILE_TIME) + ".zip";
        return new Export(fileName, bundle.zip(report), report);
    }

    /**
     * The report of the scope over the period.
     *
     * @throws IllegalArgumentException when the period ends before it starts or is longer than 400 days
     */
    public QualityReport report(Request request) {
        Objects.requireNonNull(request, "request");
        Instant now = clock.instant();
        Instant to = request.to() == null || request.to().isAfter(now) ? now : request.to();
        Instant from = request.from() != null ? request.from() : to.minus(DEFAULT_PERIOD);
        if (!to.isAfter(from)) {
            throw new IllegalArgumentException("The period of the report ends before it starts");
        }
        if (Duration.between(from, to).compareTo(MAX_PERIOD) > 0) {
            throw new IllegalArgumentException("The period of the report is longer than " + MAX_PERIOD.toDays()
                    + " days");
        }
        String scope = request.scope() != null && !request.scope().isBlank() ? request.scope().trim()
                : PromptVersionService.PLATFORM_SCOPE;
        String tenant = PromptVersionService.PLATFORM_SCOPE.equals(scope) ? null : scope;
        String exportedBy = request.exportedBy() != null && !request.exportedBy().isBlank()
                ? request.exportedBy().trim() : "system";

        QualityReportMasking masking = new QualityReportMasking(random);
        masking.know(caseSubjects(scope));
        PromptQualityMeasurements runner = measurements.get();
        ZeroTrustConsoleService operations = console.get();
        PromptQualityStatus.Status state = status.status(scope, periodName(Duration.between(from, to)), tenant);

        QualityReport.Reversals reversals = reversals(from, to, tenant, masking);
        List<VersionPeriod> periods = operations != null ? operations.versionPeriods(from, to, tenant) : List.of();
        QualityReport.Accuracy accuracy = accuracy(scope, from, to, state, runner, periods, masking);
        QualityReport.CaseSets caseSets = caseSets(scope, from, to, state, accuracy);
        QualityReport.Monitoring monitoring = monitoring(scope, from, to, state, operations, periods, accuracy);
        QualityReport.History history = history(scope, from, to, masking);

        QualityGateSettings settings = gate.settings();
        QualityReport.Header header = new QualityReport.Header(now.toString(), exportedBy, scope, PROMPT,
                from.toString(), to.toString(), tenant, answers(),
                new QualityReport.Gate(gate.mode().name(), settings.modelLessLimit(), settings.significance(),
                        settings.minimumStopRoots(), settings.minimumAllowRoots()),
                runner != null ? new QualityReport.ModelSetting(runner.settingsHash(), runner.settingsNow()) : null,
                runner != null, operations != null);
        QualityReport report = new QualityReport(QualityReport.FORMAT, header, accuracy, caseSets, monitoring,
                reversals, history, new QualityReport.Masking(QualityReportMasking.RULES, masking.subjects(),
                masking.scrubbedTexts()));
        log.info("[PromptQualityReport] Report of {} from {} to {} made for {}: {} measurements, {} reversals,"
                        + " {} audit records", scope, from, to, exportedBy, accuracy.measurements().size(),
                reversals.entries().size(), history.audit().size());
        return report;
    }

    // ----- 1. the declaration of the accuracy metrics -----

    private QualityReport.Accuracy accuracy(String scope, Instant from, Instant to, PromptQualityStatus.Status now,
                                            @Nullable PromptQualityMeasurements runner, List<VersionPeriod> periods,
                                            QualityReportMasking masking) {
        String version = now.version();
        PromptVersionRecord record = record(scope, version);
        QualityReport.VersionInfo info = record != null ? new QualityReport.VersionInfo(record.name(),
                record.number(), record.provider(), record.origin(), record.createdBy(),
                record.createdAt().toString(), record.contentHash(), masking.text(record.title())) : null;
        List<QualityReport.MeasurementRow> rows = new ArrayList<>();
        int leftOut = 0;
        if (runner != null) {
            List<PromptQualityMeasurements.Measure> finished = runner.finished(scope, PROMPT, from, to,
                    MEASUREMENT_LIMIT + 1);
            leftOut = finished.size() > MEASUREMENT_LIMIT ? countFinished(scope, from, to) - MEASUREMENT_LIMIT : 0;
            for (PromptQualityMeasurements.Measure measure : finished.stream().limit(MEASUREMENT_LIMIT).toList()) {
                rows.add(row(runner, measure, masking));
            }
        }
        String missing = version == null ? "NO_VERSION_IN_USE" : runner == null ? "UNMEASURABLE"
                : now.measurement() == null ? cases.latestPublished(scope, PROMPT).isEmpty() ? "NO_CASE_SET"
                : "NO_MEASUREMENT" : null;
        List<QualityReport.Comparison> comparisons = version != null
                ? comparisons(scope, version, now, periods) : List.of();
        if (now.measurement() == null || runner == null) {
            return new QualityReport.Accuracy(missing, version, now.source(), now.state().name(), now.measuring(),
                    info, null, null, List.of(), comparisons, rows, leftOut);
        }
        PromptQualityStatus.Measurement measurement = now.measurement();
        QualityReport.Declared declared = new QualityReport.Declared(measurement.id(), measurement.version(),
                measurement.caseSetVersion(), measurement.repeats(), measurement.modelSetting(),
                measurement.startReason(), text(measurement.finishedAt()), measurement.fresh(),
                measurement.changedSettings(), measurement.firstAnswer(), measurement.finalAction(),
                measurement.secondAnalysisCases().size(), measurement.secondAnalysisFirstAnswer(),
                measurement.missingCases());
        QualityGateSettings settings = gate.settings();
        int stopRoots = measurement.firstAnswer().rates().get(QualityMetric.MISS.name()).roots();
        int allowRoots = measurement.firstAnswer().rates().get(QualityMetric.FALSE_STOP.name()).roots();
        QualityReport.Sufficiency sufficiency = new QualityReport.Sufficiency(stopRoots, settings.minimumStopRoots(),
                allowRoots, settings.minimumAllowRoots(), stopRoots >= settings.minimumStopRoots()
                && allowRoots >= settings.minimumAllowRoots());
        return new QualityReport.Accuracy(null, version, now.source(), now.state().name(), now.measuring(), info,
                declared, sufficiency, alone(runner, measurement.id(), record), comparisons, rows, leftOut);
    }

    private int countFinished(String scope, Instant from, Instant to) {
        Integer count = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_measure where"
                + " registry_scope = ? and prompt_key = ? and finished_at >= ? and finished_at < ?", Integer.class,
                scope, PROMPT, Timestamp.from(from), Timestamp.from(to));
        return count != null ? count : 0;
    }

    private QualityReport.MeasurementRow row(PromptQualityMeasurements runner, PromptQualityMeasurements.Measure measure,
                                             QualityReportMasking masking) {
        PromptQualityStatus.Score first = null;
        PromptQualityStatus.Score last = null;
        if (PromptQualityMeasurements.DONE.equals(measure.status())) {
            Optional<PromptQualityMeasurements.Result> result = runner.result(measure.id());
            if (result.isPresent()) {
                first = PromptQualityStatus.Score.of(result.get().firstAnswer());
                last = PromptQualityStatus.Score.of(result.get().finalAction());
            }
        }
        return new QualityReport.MeasurementRow(measure.id(), measure.versionName(), measure.caseSetVersion(),
                measure.repeats(), measure.modelSettingOrSettings(), measure.status(), measure.startReason(),
                measure.createdBy(), text(measure.finishedAt()), measure.answered(), masking.text(measure.failure()),
                first, last);
    }

    /** The conditions of the gate one measurement decides by itself, on the measurement declared. */
    private List<QualityReport.Finding> alone(PromptQualityMeasurements runner, long measureId,
                                              @Nullable PromptVersionRecord record) {
        Optional<PromptQualityMeasurements.Result> result = runner.result(measureId);
        if (result.isEmpty()) {
            return List.of();
        }
        List<QualityCase> items = cases.published(result.get().measure().caseSetId())
                .map(set -> cases.read(set).cases().cases()).orElse(List.of());
        QualityGateResult evaluated = QualityGateEvaluator.evaluate(new QualityGateInput(items, null,
                result.get().measurement(), null, gate.settings(), record != null ? record.createdAt() : null));
        return ALONE.stream().map(evaluated::finding).map(PromptQualityReports::finding).toList();
    }

    /**
     * The version in use against each version that decided before it: the one it replaced, then those that decided
     * in the period, the most decisions first.
     */
    private List<QualityReport.Comparison> comparisons(String scope, String version, PromptQualityStatus.Status now,
                                                       List<VersionPeriod> periods) {
        Set<String> before = new LinkedHashSet<>();
        if (now.operation() != null && now.operation().previousVersion() != null) {
            before.add(now.operation().previousVersion());
        }
        periods.stream().map(VersionPeriod::version).forEach(before::add);
        before.remove(version);
        List<QualityReport.Comparison> comparisons = new ArrayList<>();
        for (String earlier : before) {
            QualityGateVerdict verdict = gate.assess(scope, PROMPT, version, earlier);
            QualityGateResult result = verdict.result();
            List<QualityReport.MetricComparison> metrics = new ArrayList<>();
            List<QualityReport.Finding> findings = new ArrayList<>();
            QualityCaseChanges changes = QualityCaseChanges.none();
            if (result != null) {
                for (QualityComparison comparison : result.comparisons().values()) {
                    metrics.add(metric(comparison));
                }
                result.findings().stream().map(PromptQualityReports::finding).forEach(findings::add);
                changes = result.changes();
            }
            List<String> sides = verdict.sides().stream()
                    .map(side -> side == QualityGateSide.CANDIDATE ? "IN_USE" : "BEFORE").sorted().toList();
            comparisons.add(new QualityReport.Comparison(earlier,
                    verdict.measurement() != null ? verdict.measurement().name()
                            : QualityMeasurementState.MISSING.name(), sides, verdict.detail(),
                    verdict.verdict().name(), metrics, findings, changes));
        }
        return comparisons;
    }

    private static QualityReport.MetricComparison metric(QualityComparison comparison) {
        return new QualityReport.MetricComparison(comparison.metric().name(), comparison.verdict().name(),
                number(comparison.candidateValue()), number(comparison.currentValue()),
                number(comparison.difference()), number(comparison.noiseWidth()), comparison.pairedCases(),
                comparison.pairedRoots(), comparison.worseRoots(), comparison.betterRoots(),
                number(comparison.worseProbability()), number(comparison.betterProbability()));
    }

    private static QualityReport.Finding finding(QualityGateFinding finding) {
        return new QualityReport.Finding(finding.condition().name(), finding.status().name(), finding.figures(),
                finding.caseKeys());
    }

    // ----- 2. the case set versions -----

    private QualityReport.CaseSets caseSets(String scope, Instant from, Instant to, PromptQualityStatus.Status now,
                                            QualityReport.Accuracy accuracy) {
        PromptQualityCases.Counts counts = now.cases();
        QualityReport.Inventory inventory = new QualityReport.Inventory(counts.kept(), counts.operation(),
                counts.secondAnalysis(), counts.pending(), cases.twoPersonConfirmation(), cases.defaultSet().version(),
                cases.defaultSet().cases().size());
        Set<String> measured = new LinkedHashSet<>();
        if (accuracy.declared() != null) {
            measured.add(accuracy.declared().caseSetVersion());
        }
        accuracy.measurements().forEach(row -> measured.add(row.caseSetVersion()));
        List<PromptQualityCases.PublishedSet> published = cases.publishedSets(scope, PROMPT);
        if (published.isEmpty()) {
            return new QualityReport.CaseSets("NO_CASE_SET", inventory, List.of());
        }
        Set<String> secondAnalysis = cases.list(scope, PROMPT).stream().filter(PromptQualityCases.Kept::secondAnalysis)
                .map(PromptQualityCases.Kept::key).collect(Collectors.toSet());
        List<QualityReport.SetRow> sets = new ArrayList<>();
        for (int index = 0; index < published.size(); index++) {
            PromptQualityCases.PublishedSet set = published.get(index);
            List<String> reasons = new ArrayList<>();
            if (index == 0) {
                reasons.add("LATEST");
            }
            if (!set.publishedAt().isBefore(from) && set.publishedAt().isBefore(to)) {
                reasons.add("PUBLISHED_IN_PERIOD");
            }
            if (measured.contains(set.version())) {
                reasons.add("MEASURED");
            }
            if (!reasons.isEmpty()) {
                sets.add(setRow(set, reasons, secondAnalysis));
            }
        }
        return new QualityReport.CaseSets(null, inventory, sets);
    }

    private QualityReport.SetRow setRow(PromptQualityCases.PublishedSet set, List<String> reasons,
                                        Set<String> secondAnalysis) {
        PromptQualityCases.ReadSet read = cases.read(set);
        Map<String, Integer> byOrigin = new TreeMap<>();
        Map<String, Integer> byGrade = new TreeMap<>();
        Map<String, Integer> byClass = new TreeMap<>();
        Map<String, Integer> byKind = new TreeMap<>();
        Set<String> stopRoots = new LinkedHashSet<>();
        Set<String> allowRoots = new LinkedHashSet<>();
        int marked = 0;
        for (QualityCase item : read.cases().cases()) {
            byOrigin.merge(item.origin().name(), 1, Integer::sum);
            byGrade.merge(item.grade().name(), 1, Integer::sum);
            byClass.merge(item.expectation().classification().name(), 1, Integer::sum);
            byKind.merge(item.expectation().kind().name(), 1, Integer::sum);
            (item.shouldStop() ? stopRoots : allowRoots).add(item.rootKey());
            if (secondAnalysis.contains(item.key())) {
                marked++;
            }
        }
        return new QualityReport.SetRow(set.id(), set.version(), set.name(), set.caseCount(), set.defaultSetVersion(),
                set.defaultCaseCount(), set.publishedBy(), set.publishedAt().toString(), reasons,
                read.cases().cases().size(), read.missing(), byOrigin, byGrade, byClass, byKind, stopRoots.size(),
                allowRoots.size(), marked);
    }

    // ----- 3. the monitoring after the release -----

    private QualityReport.Monitoring monitoring(String scope, Instant from, Instant to, PromptQualityStatus.Status now,
                                                @Nullable ZeroTrustConsoleService operations,
                                                List<VersionPeriod> periods, QualityReport.Accuracy accuracy) {
        List<QualityReport.VersionOperation> rows = new ArrayList<>();
        for (VersionPeriod period : periods) {
            Map<String, PromptQualityStatus.Rate> rates = new LinkedHashMap<>();
            for (PeriodRate rate : period.rates()) {
                rates.put(rate.key(), operationRate(rate.events(), rate.trials()));
            }
            rows.add(new QualityReport.VersionOperation(period.version(), period.version().equals(now.version()),
                    period.firstHour(), period.lastHour(), period.decisions(), rates));
        }
        String missing = operations == null ? "NO_OPERATIONS" : rows.isEmpty() ? "NO_DECISIONS_IN_PERIOD" : null;
        QualityScheduledMeasurement.Kept latest = now.latestRemeasure();
        QualityReport.Remeasure remeasure = latest != null ? new QualityReport.Remeasure(latest.measureId(),
                latest.comparedMeasureId(), latest.verdict().name(), latest.startReason(),
                latest.comparedAt().toString(), latest.detail()) : null;
        PromptQualityCauses classifier = causes.get();
        QualityReport.Causes measurementCauses;
        QualityReport.Causes decisionCauses;
        if (classifier == null) {
            measurementCauses = new QualityReport.Causes("NO_CAUSES", null, List.of(), 0, 0);
            decisionCauses = new QualityReport.Causes("NO_CAUSES", null, List.of(), 0, 0);
        }
        else {
            measurementCauses = accuracy.declared() == null
                    ? new QualityReport.Causes("NO_MEASUREMENT", null, List.of(), 0, 0)
                    : classifier.ofMeasurement(accuracy.declared().measureId()).map(PromptQualityReports::causes)
                    .orElseGet(() -> new QualityReport.Causes("NO_MEASUREMENT", null, List.of(), 0, 0));
            decisionCauses = causes(classifier.ofDecisions(scope, from, to));
        }
        return new QualityReport.Monitoring(missing, rows, now.operation(), remeasure, text(now.nextScheduled()),
                now.toCheck(), now.pendingReviews(), measurementCauses, decisionCauses);
    }

    private static QualityReport.Causes causes(PromptQualityCauses.Summary summary) {
        List<QualityReport.CauseCount> counts = summary.counts().stream().map(count -> new QualityReport.CauseCount(
                count.cause().name(), count.fix() != null ? count.fix().name() : null, count.count(),
                count.notComputed())).toList();
        return new QualityReport.Causes(null, summary.measureId(), counts, summary.causes().size(),
                summary.withoutRecord());
    }

    /** An operation metric with its 95% interval over the decisions, each decision one in the sample. */
    static PromptQualityStatus.Rate operationRate(long events, long trials) {
        if (trials <= 0) {
            return new PromptQualityStatus.Rate(events, trials, null, null, null, 0);
        }
        int sample = (int) Math.min(trials, Integer.MAX_VALUE);
        double value = (double) events / trials;
        double[] interval = QualityStatistics.wilson(value, sample);
        return new PromptQualityStatus.Rate(events, trials, value, number(interval[0]), number(interval[1]), sample);
    }

    // ----- 4. the decisions people overturned -----

    private record Outcome(String kind, @Nullable String observationId, @Nullable String userId,
                           @Nullable String reason, @Nullable String actor, @Nullable String note, Instant occurredAt,
                           boolean found, @Nullable Instant decidedAt, @Nullable String action,
                           @Nullable String proposed, @Nullable String version, @Nullable String decisionUser) {
    }

    private static final String DECISION_COLUMNS = ", d.observation_id as found_id, d.created_at as decided_at,"
            + " d.final_action, d.proposed_action, d.prompt_bundle_version, d.user_id as decision_user";

    private QualityReport.Reversals reversals(Instant from, Instant to, @Nullable String tenant,
                                              QualityReportMasking masking) {
        String tenantClause = tenant != null ? " and o.tenant_id = ?" : "";
        List<Object> overturned = new ArrayList<>(List.of(RELEASED, BREACH, Timestamp.from(from), Timestamp.from(to)));
        if (tenant != null) {
            overturned.add(tenant);
        }
        List<Outcome> outcomes = new ArrayList<>(jdbc.get().query("select x.*" + DECISION_COLUMNS + " from (select"
                + " distinct on (coalesce(o.observation_id, o.request_id), o.outcome_kind) o.outcome_kind,"
                + " o.observation_id, o.user_id, o.evaluation_reason, o.actor, o.note, o.occurred_at from"
                + " ctxa_zt_decision_outcome o where o.outcome_kind in (?, ?) and o.occurred_at >= ? and"
                + " o.occurred_at < ? and coalesce(o.observation_id, o.request_id) is not null" + tenantClause
                + " order by coalesce(o.observation_id, o.request_id), o.outcome_kind, o.occurred_at, o.outcome_id) x"
                + " left join ctxa_ai_security_decision_observation d on d.observation_id = x.observation_id",
                PromptQualityReports::outcome, overturned.toArray()));
        // The latest rating of a decision counts, as the causes of the rated decisions read it.
        List<Object> rated = new ArrayList<>(List.of(VALID, INVALID, Timestamp.from(from), Timestamp.from(to)));
        if (tenant != null) {
            rated.add(tenant);
        }
        List<Outcome> ratings = jdbc.get().query("select x.*" + DECISION_COLUMNS + " from (select latest.* from"
                + " (select distinct on (coalesce(o.observation_id, o.request_id)) o.outcome_kind, o.observation_id,"
                + " o.user_id, o.evaluation_reason, o.actor, o.note, o.occurred_at, o.tenant_id from"
                + " ctxa_zt_decision_outcome o where o.outcome_kind in (?, ?) and o.occurred_at >= ? and"
                + " coalesce(o.observation_id, o.request_id) is not null order by coalesce(o.observation_id,"
                + " o.request_id), o.occurred_at desc, o.created_at desc, o.outcome_id desc) latest where"
                + " latest.occurred_at < ?" + tenantClause.replace("o.", "latest.") + ") x left join"
                + " ctxa_ai_security_decision_observation d on d.observation_id = x.observation_id",
                PromptQualityReports::outcome, rated.toArray());
        long invalid = ratings.stream().filter(rating -> INVALID.equals(rating.kind())).count();
        ratings.stream().filter(rating -> INVALID.equals(rating.kind())).forEach(outcomes::add);
        outcomes.forEach(outcome -> masking.know(List.of(Objects.toString(outcome.userId(), ""),
                Objects.toString(outcome.decisionUser(), ""))));
        outcomes.sort(Comparator.comparing(Outcome::occurredAt).reversed()
                .thenComparing(outcome -> Objects.toString(outcome.observationId(), "")));

        List<QualityReport.KindSummary> kinds = new ArrayList<>();
        for (String kind : KINDS) {
            Map<String, Integer> byAction = new TreeMap<>();
            Map<String, Integer> byVersion = new TreeMap<>();
            Map<String, Integer> byReason = new TreeMap<>();
            int decisions = 0;
            for (Outcome outcome : outcomes) {
                if (!kind.equals(outcome.kind())) {
                    continue;
                }
                decisions++;
                byAction.merge(outcome.found() ? Objects.toString(outcome.action(), "UNKNOWN") : "NO_RECORD", 1,
                        Integer::sum);
                byVersion.merge(outcome.found() ? Objects.toString(outcome.version(), "UNKNOWN") : "NO_RECORD", 1,
                        Integer::sum);
                if (INVALID.equals(kind)) {
                    byReason.merge(Objects.toString(outcome.reason(), "UNKNOWN"), 1, Integer::sum);
                }
            }
            kinds.add(new QualityReport.KindSummary(kind, decisions, byAction, byVersion, byReason));
        }
        List<QualityReport.ReversedDecision> entries = new ArrayList<>();
        for (Outcome outcome : outcomes.stream().limit(REVERSAL_LIMIT).toList()) {
            entries.add(new QualityReport.ReversedDecision(outcome.occurredAt().toString(), outcome.kind(),
                    outcome.observationId(), outcome.found(), text(outcome.decidedAt()), outcome.action(),
                    outcome.proposed(), outcome.version(), outcome.reason(), outcome.actor(),
                    outcome.note() != null && !outcome.note().isBlank(), masking.subject(outcome.userId() != null
                    ? outcome.userId() : outcome.decisionUser())));
        }
        return new QualityReport.Reversals(outcomes.isEmpty() ? "NO_REVERSALS_IN_PERIOD" : null, kinds,
                operationRate(invalid, ratings.size()), entries, Math.max(0, outcomes.size() - REVERSAL_LIMIT));
    }

    private static Outcome outcome(ResultSet rs, int row) throws SQLException {
        return new Outcome(rs.getString("outcome_kind"), rs.getString("observation_id"), rs.getString("user_id"),
                rs.getString("evaluation_reason"), rs.getString("actor"), rs.getString("note"),
                rs.getTimestamp("occurred_at").toInstant(), rs.getString("found_id") != null,
                instant(rs.getTimestamp("decided_at")), rs.getString("final_action"), rs.getString("proposed_action"),
                rs.getString("prompt_bundle_version"), rs.getString("decision_user"));
    }

    // ----- 5. the changes and approvals -----

    private QualityReport.History history(String scope, Instant from, Instant to, QualityReportMasking masking) {
        Object[] period = {Timestamp.from(from), Timestamp.from(to)};
        List<QualityReport.AuditEntry> audit = jdbc.get().query("select timestamp, principal_name, action,"
                + " resource_identifier, reason from ctxa_audit_log where (action like 'PROMPT_VERSION_%' or action"
                + " like 'PROMPT_QUALITY_%') and resource_identifier like ? and coalesce(contexa_safe_jsonb(details)"
                + " ->> 'scope', ?) = ? and timestamp >= ? and timestamp < ? order by timestamp desc, id desc limit ?",
                (rs, row) -> new QualityReport.AuditEntry(rs.getTimestamp(1).toInstant().toString(), rs.getString(2),
                        rs.getString(3), rs.getString(4), masking.text(rs.getString(5))),
                PROMPT + "@%", scope, scope, period[0], period[1], AUDIT_LIMIT + 1);
        Map<String, Integer> byAction = new TreeMap<>();
        jdbc.get().query("select action, count(*) from ctxa_audit_log where (action like 'PROMPT_VERSION_%' or action"
                + " like 'PROMPT_QUALITY_%') and resource_identifier like ? and coalesce(contexa_safe_jsonb(details)"
                + " ->> 'scope', ?) = ? and timestamp >= ? and timestamp < ? group by action",
                (rs, row) -> Map.entry(Objects.toString(rs.getString(1), "UNKNOWN"), rs.getInt(2)),
                PROMPT + "@%", scope, scope, period[0], period[1])
                .forEach(entry -> byAction.put(entry.getKey(), entry.getValue()));
        int auditTotal = byAction.values().stream().mapToInt(Integer::intValue).sum();

        List<QualityReport.Transition> transitions = jdbc.get().query("select created_at, prompt_version,"
                + " current_release_status, target_release_status, workflow_state, gate_state, approval_channel,"
                + " actor_name, rationale, blockers_json from ctxa_prompt_governance_release_workflow where"
                + " registry_scope = ? and prompt_key = ? and created_at >= ? and created_at < ? order by created_at"
                + " desc, id desc limit ?", (rs, row) -> new QualityReport.Transition(
                        rs.getTimestamp(1).toInstant().toString(), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6), OVERRIDDEN.equals(rs.getString(6)), rs.getString(7),
                        rs.getString(8), masking.text(rs.getString(9)), masking.text(rs.getString(10))),
                scope, PROMPT, period[0], period[1], TRANSITION_LIMIT + 1);
        int[] transitionCounts = jdbc.get().queryForObject("select count(*), count(*) filter (where gate_state = ?)"
                + " from ctxa_prompt_governance_release_workflow where registry_scope = ? and prompt_key = ? and"
                + " created_at >= ? and created_at < ?", (rs, row) -> new int[] {rs.getInt(1), rs.getInt(2)},
                OVERRIDDEN, scope, PROMPT, period[0], period[1]);

        List<QualityReport.Rollback> rollbacks = jdbc.get().query("select execution_key, executed_at, from_version,"
                + " to_version, actor, reason, emergency, status, approved_by, approved_at from"
                + " ctxa_prompt_governance_rollback_execution where registry_scope = ? and prompt_key = ? and"
                + " executed_at >= ? and executed_at < ? order by executed_at desc limit ?", (rs, row) ->
                new QualityReport.Rollback(rs.getString(1), rs.getTimestamp(2).toInstant().toString(),
                        rs.getString(3), rs.getString(4), rs.getString(5), masking.text(rs.getString(6)),
                        rs.getBoolean(7), rs.getString(8), rs.getString(9), text(instant(rs.getTimestamp(10)))),
                scope, PROMPT, period[0], period[1], ROLLBACK_LIMIT + 1);
        Integer rollbackTotal = jdbc.get().queryForObject("select count(*) from"
                + " ctxa_prompt_governance_rollback_execution where registry_scope = ? and prompt_key = ? and"
                + " executed_at >= ? and executed_at < ?", Integer.class, scope, PROMPT, period[0], period[1]);

        return new QualityReport.History(audit.stream().limit(AUDIT_LIMIT).toList(),
                Math.max(0, auditTotal - AUDIT_LIMIT), byAction,
                transitions.stream().limit(TRANSITION_LIMIT).toList(),
                Math.max(0, transitionCounts[0] - TRANSITION_LIMIT), transitionCounts[1],
                rollbacks.stream().limit(ROLLBACK_LIMIT).toList(),
                Math.max(0, (rollbackTotal != null ? rollbackTotal : 0) - ROLLBACK_LIMIT));
    }

    private static final String OVERRIDDEN = "QUALITY_GATE_OVERRIDDEN";

    // ----- helpers -----

    /** The persons the scope's cases are about: their identifiers are replaced wherever a free text names them. */
    private List<String> caseSubjects(String scope) {
        return jdbc.get().queryForList("select distinct subject_user_id from ctxa_prompt_version_case where"
                + " registry_scope = ? and subject_user_id is not null", String.class, scope);
    }

    @Nullable
    private PromptVersionRecord record(String scope, @Nullable String version) {
        OptionalInt number = PromptVersionNames.number(version);
        return number.isPresent() ? versions.find(scope, PROMPT, number.getAsInt()).orElse(null) : null;
    }

    /** Each question of the regulations and the section of the report that answers it. */
    private static Map<String, String> answers() {
        Map<String, String> answers = new LinkedHashMap<>();
        answers.put("ACCURACY_DECLARATION", QualityReport.ACCURACY_DECLARATION);
        answers.put("POST_MARKET_MONITORING", QualityReport.POST_MARKET_MONITORING);
        answers.put("OVERTURNED_DECISIONS", QualityReport.OVERTURNED_DECISIONS);
        return answers;
    }

    /** The console's period of the version change closest to the report's: a day, a week, 30 or 90 days. */
    static String periodName(Duration length) {
        if (length.compareTo(Duration.ofDays(1)) <= 0) {
            return "day";
        }
        if (length.compareTo(Duration.ofDays(7)) <= 0) {
            return "week";
        }
        return length.compareTo(Duration.ofDays(30)) <= 0 ? "month" : "quarter";
    }

    @Nullable
    private static Double number(double value) {
        return Double.isNaN(value) || Double.isInfinite(value) ? null : value;
    }

    @Nullable
    private static String text(@Nullable Instant instant) {
        return instant != null ? instant.toString() : null;
    }

    @Nullable
    private static Instant instant(@Nullable Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
