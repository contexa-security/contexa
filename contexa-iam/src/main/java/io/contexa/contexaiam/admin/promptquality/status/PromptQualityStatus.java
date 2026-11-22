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
package io.contexa.contexaiam.admin.promptquality.status;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexacore.std.components.prompt.quality.QualityRemeasureComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityScorer;
import io.contexa.contexacore.std.components.prompt.quality.QualitySpread;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.QualityModelSetting;
import io.contexa.contexaiam.admin.promptquality.measure.QualityScheduledMeasurement;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionChange;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Plan 3.6, 3.8: what the state of quality shows of the version the security decision decides with in a scope: its
 * latest measurement on the case set the measurements of the scope run on, with every rate as numerator, denominator
 * and 95% interval on both bases, and the operation metrics of the hourly table beside those of the version it
 * replaced; and what there is to check. It is the data the screen draws; the screen is not here.
 *
 * <ul>
 * <li>The measurement read is the latest one done under the settings this server runs, else the latest done under
 * other settings, which is stale (the settings that differ are named). Without one done it is waited for, missing,
 * or this application cannot measure.</li>
 * <li>The cases promoted from a decision the second analysis decided are counted apart, with their first-answer
 * rates.</li>
 * <li>To check: a stale measurement, a measurement missing or waited for, a version measured again that came out worse
 * or changed against the measurement before, the cases waiting for another administrator's confirmation, and the
 * decisions waiting for review.</li>
 * </ul>
 */
public class PromptQualityStatus {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final int RECENT = 50;
    private static final List<String> SEVERITIES = List.of("BAD", "WARN", "INFO");

    /** One rate: its numerator and denominator, its value and its 95% interval over the roots; null values when empty. */
    public record Rate(long events, long trials, @Nullable Double value, @Nullable Double lower,
                       @Nullable Double upper, int roots) {

        static Rate of(QualityRate rate) {
            if (rate == null) {
                return new Rate(0, 0, null, null, null, 0);
            }
            return new Rate(rate.events(), rate.trials(), number(rate.value()), number(rate.lower()),
                    number(rate.upper()), rate.roots());
        }
    }

    /** The median and the 95th value of a measure of the answers, over how many there were. */
    public record Spread(int count, @Nullable Double median, @Nullable Double ninetyFifth) {

        static Spread of(QualitySpread spread) {
            return spread == null ? new Spread(0, null, null)
                    : new Spread(spread.count(), number(spread.median()), number(spread.ninetyFifth()));
        }
    }

    /** The rates of a measurement on one basis, with the spreads of the decision time and the answer tokens. */
    public record Score(Map<String, Rate> rates, Spread decisionMillis, Spread answerTokens, int answers,
                        int scoredAnswers, int incompleteAnswers, int cases, int unmeasuredCases, int roots) {

        static Score of(QualityScore score) {
            Map<String, Rate> rates = new LinkedHashMap<>();
            for (QualityMetric metric : QualityMetric.values()) {
                rates.put(metric.name(), Rate.of(score.rate(metric)));
            }
            return new Score(rates, Spread.of(score.decisionMillis()), Spread.of(score.answerTokens()),
                    score.answers(), score.scoredAnswers(), score.incompleteAnswers(), score.cases(),
                    score.unmeasuredCases(), score.roots());
        }
    }

    /**
     * The latest measurement of the version in use.
     *
     * @param fresh                  whether it ran under the settings this server runs
     * @param changedSettings        the settings that differ from this server's, each before and now; empty when fresh
     * @param secondAnalysisCases    the cases of its set promoted from a decision the second analysis decided
     * @param secondAnalysisFirstAnswer their first-answer rates, counted apart; null without such cases
     * @param missingCases           the cases of its set that cannot be read any more
     */
    public record Measurement(long id, String version, String caseSetVersion, int repeats, String modelSetting,
                              @Nullable String startReason, @Nullable Instant finishedAt, boolean fresh,
                              Map<String, List<String>> changedSettings, Score firstAnswer, Score finalAction,
                              List<String> secondAnalysisCases, @Nullable Score secondAnalysisFirstAnswer,
                              List<String> missingCases) {
    }

    /**
     * Something to check, worst first.
     *
     * @param kind     MEASUREMENT_STALE, MEASUREMENT_MISSING, BASELINE_PENDING, UNMEASURABLE, REMEASURE_WORSE,
     *                 REMEASURE_CHANGED, CASES_PENDING, REVIEW_PENDING
     * @param severity BAD, WARN or INFO
     * @param count    how many it is about
     * @param figures  what it rests on
     */
    public record ToCheck(String kind, String severity, long count, Map<String, Object> figures) {
    }

    /**
     * The state of quality of a scope.
     *
     * @param version         the version deciding, or null when no version of the database decides
     * @param source          what chose it
     * @param state           whether its latest measurement is there and current
     * @param measuring       whether a measurement of it under these settings waits or runs
     * @param operation       the operation metrics beside those of the version it replaced; null without the console
     * @param latestRemeasure the latest comparison of the version measured again with its measurement before
     * @param nextScheduled   when the version in use is measured again next on schedule, or null when it is off
     */
    public record Status(String scope, String prompt, @Nullable String version, @Nullable String source,
                         QualityMeasurementState state, boolean measuring, @Nullable Measurement measurement,
                         @Nullable VersionChange operation, @Nullable QualityScheduledMeasurement.Kept latestRemeasure,
                         @Nullable Instant nextScheduled, PromptQualityCases.Counts cases, long pendingReviews,
                         List<ToCheck> toCheck) {
    }

    private final PromptVersionService versions;
    private final JdbcPromptVersionCatalog catalog;
    private final PromptQualityCases cases;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final Supplier<QualityScheduledMeasurement> scheduled;
    private final Supplier<ZeroTrustConsoleService> console;
    private final Supplier<ZeroTrustDecisionRecords> decisions;

    /**
     * @param measurements the measurement runner; a supplier of null when this application cannot replay decisions
     * @param scheduled    the measurements taken again; a supplier of null when there are none
     * @param console      the console's hourly table; a supplier of null when the console is not here
     * @param decisions    the decision records with the review queue; a supplier of null when they are not here
     */
    public PromptQualityStatus(PromptVersionService versions, JdbcPromptVersionCatalog catalog,
                               PromptQualityCases cases, Supplier<PromptQualityMeasurements> measurements,
                               Supplier<QualityScheduledMeasurement> scheduled,
                               Supplier<ZeroTrustConsoleService> console, Supplier<ZeroTrustDecisionRecords> decisions) {
        this.versions = Objects.requireNonNull(versions, "versions");
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.measurements = measurements != null ? measurements : () -> null;
        this.scheduled = scheduled != null ? scheduled : () -> null;
        this.console = console != null ? console : () -> null;
        this.decisions = decisions != null ? decisions : () -> null;
    }

    /**
     * The state of quality of the scope.
     *
     * @param scope  the scope of the prompt versions, or null for the platform
     * @param period the length of the operation periods: day, week (the default), month or quarter
     * @param tenant the tenant the operation metrics are read for, or null for all
     */
    public Status status(@Nullable String scope, @Nullable String period, @Nullable String tenant) {
        String scopeName = scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
        PromptBundleSelection selection = catalog.decidingSelection(scopeName, PROMPT);
        String version = selection != null ? selection.bundleVersion() : null;
        OptionalInt number = PromptVersionNames.number(version);
        PromptVersionRecord record = number.isPresent()
                ? versions.find(scopeName, PROMPT, number.getAsInt()).orElse(null) : null;
        PromptQualityMeasurements runner = measurements.get();
        PromptQualityCases.Counts counts = cases.counts(scopeName, PROMPT);
        ZeroTrustDecisionRecords records = decisions.get();
        long pendingReviews = records != null ? records.reviewPending() : 0;
        QualityScheduledMeasurement again = scheduled.get();

        QualityMeasurementState state;
        boolean measuring = false;
        Measurement measurement = null;
        if (runner == null) {
            state = QualityMeasurementState.UNMEASURABLE;
        }
        else if (record == null) {
            state = QualityMeasurementState.MISSING;
        }
        else {
            Optional<PromptQualityCases.PublishedSet> set = cases.latestPublished(scopeName, PROMPT);
            String now = runner.settingsHash();
            PromptQualityMeasurements.Measure fresh = null;
            PromptQualityMeasurements.Measure stale = null;
            if (set.isPresent()) {
                for (PromptQualityMeasurements.Measure row : runner.recent(scopeName, PROMPT, record.number(), RECENT)) {
                    if (row.caseSetId() != set.get().id() || !row.versionContentHash().equals(record.contentHash())) {
                        continue;
                    }
                    boolean sameSettings = row.settingsHash().equals(now);
                    if (PromptQualityMeasurements.QUEUED.equals(row.status())
                            || PromptQualityMeasurements.RUNNING.equals(row.status())) {
                        measuring = measuring || sameSettings;
                    }
                    else if (PromptQualityMeasurements.DONE.equals(row.status())) {
                        if (sameSettings && fresh == null) {
                            fresh = row;
                        }
                        else if (!sameSettings && stale == null) {
                            stale = row;
                        }
                    }
                }
            }
            PromptQualityMeasurements.Measure read = fresh != null ? fresh : stale;
            state = fresh != null ? QualityMeasurementState.MEASURED : stale != null ? QualityMeasurementState.STALE
                    : measuring ? QualityMeasurementState.BASELINE_PENDING : QualityMeasurementState.MISSING;
            if (read != null) {
                measurement = measurement(runner, scopeName, read, fresh != null);
            }
        }
        QualityScheduledMeasurement.Kept latest = again != null && record != null
                ? again.latestComparison(scopeName, PROMPT, record.number()).orElse(null) : null;
        ZeroTrustConsoleService operations = console.get();
        VersionChange operation = operations != null && version != null
                ? operations.versionChange(version, period, tenant) : null;
        List<ToCheck> toCheck = toCheck(state, measuring, measurement, latest, counts, pendingReviews, version);
        return new Status(scopeName, PROMPT, version, selection != null ? selection.source().name() : null, state,
                measuring, measurement, operation, latest, again != null ? again.nextScheduled() : null, counts,
                pendingReviews, toCheck);
    }

    private Measurement measurement(PromptQualityMeasurements runner, String scope,
                                    PromptQualityMeasurements.Measure row, boolean fresh) {
        PromptQualityMeasurements.Result result = runner.result(row.id()).orElseThrow();
        Set<String> secondAnalysis = cases.list(scope, PROMPT).stream().filter(PromptQualityCases.Kept::secondAnalysis)
                .map(PromptQualityCases.Kept::key).collect(Collectors.toSet());
        List<QualityCase> measured = cases.published(row.caseSetId()).map(set -> cases.read(set).cases().cases())
                .orElse(List.of());
        List<QualityCase> marked = measured.stream().filter(item -> secondAnalysis.contains(item.key())).toList();
        Score markedScore = marked.isEmpty() ? null : Score.of(QualityScorer.score(marked,
                result.measurement().answers(), QualityActionBasis.FIRST_ANSWER));
        Map<String, List<String>> changed = fresh ? Map.of()
                : QualityModelSetting.changed(runner.settingsOf(row.id()), runner.settingsNow());
        return new Measurement(row.id(), row.versionName(), row.caseSetVersion(), row.repeats(),
                row.modelSettingOrSettings(), row.startReason(), row.finishedAt(), fresh, changed,
                Score.of(result.firstAnswer()), Score.of(result.finalAction()),
                marked.stream().map(QualityCase::key).toList(), markedScore, result.missingCases());
    }

    private static List<ToCheck> toCheck(QualityMeasurementState state, boolean measuring,
                                         @Nullable Measurement measurement,
                                         @Nullable QualityScheduledMeasurement.Kept latest,
                                         PromptQualityCases.Counts counts, long pendingReviews,
                                         @Nullable String version) {
        List<ToCheck> found = new ArrayList<>();
        Map<String, Object> versionFigure = new LinkedHashMap<>();
        versionFigure.put("version", version);
        if (latest != null && latest.verdict() == QualityRemeasureComparison.Verdict.WORSE) {
            found.add(new ToCheck("REMEASURE_WORSE", "BAD", 1, remeasureFigures(latest)));
        }
        switch (state) {
            case STALE -> {
                Map<String, Object> figures = new LinkedHashMap<>(versionFigure);
                figures.put("changedSettings", measurement != null ? measurement.changedSettings() : Map.of());
                figures.put("measuring", measuring);
                found.add(new ToCheck("MEASUREMENT_STALE", "WARN", 1, figures));
            }
            case MISSING -> found.add(new ToCheck("MEASUREMENT_MISSING", "WARN", 1, versionFigure));
            case BASELINE_PENDING -> found.add(new ToCheck("BASELINE_PENDING", "INFO", 1, versionFigure));
            case UNMEASURABLE -> found.add(new ToCheck("UNMEASURABLE", "INFO", 1, versionFigure));
            default -> {
            }
        }
        if (latest != null && latest.verdict() == QualityRemeasureComparison.Verdict.CHANGED) {
            found.add(new ToCheck("REMEASURE_CHANGED", "WARN", 1, remeasureFigures(latest)));
        }
        if (counts.pending() > 0) {
            found.add(new ToCheck("CASES_PENDING", "WARN", counts.pending(),
                    Map.<String, Object>of("pending", counts.pending())));
        }
        if (pendingReviews > 0) {
            found.add(new ToCheck("REVIEW_PENDING", "INFO", pendingReviews,
                    Map.<String, Object>of("pending", pendingReviews)));
        }
        found.sort(Comparator.comparingInt(item -> SEVERITIES.indexOf(item.severity())));
        return found;
    }

    private static Map<String, Object> remeasureFigures(QualityScheduledMeasurement.Kept latest) {
        Map<String, Object> figures = new LinkedHashMap<>(latest.detail());
        figures.put("measureId", latest.measureId());
        figures.put("comparedMeasureId", latest.comparedMeasureId());
        figures.put("comparedAt", latest.comparedAt().toString());
        return figures;
    }

    @Nullable
    private static Double number(double value) {
        return Double.isNaN(value) || Double.isInfinite(value) ? null : value;
    }
}
