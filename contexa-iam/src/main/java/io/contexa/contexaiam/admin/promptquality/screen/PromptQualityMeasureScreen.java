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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseChanges;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseOrigin;
import io.contexa.contexacore.std.components.prompt.quality.QualityComparator;
import io.contexa.contexacore.std.components.prompt.quality.QualityComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateEvaluator;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceClassComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceClassScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityScorer;
import io.contexa.contexacore.std.components.prompt.quality.QualitySpread;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseResources;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityResourceClasses;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.AnswerSide;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Band;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Basis;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.CaseAnswers;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.CompareView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.EstimateView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Finding;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.GradeCompare;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.GradeMetrics;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Later;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Metric;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.MetricCompare;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Noise;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Part;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Pick;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Rate;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Running;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunsView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Same;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.SetOption;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Side;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Split;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.SplitRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Splits;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Start;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.TimeCompare;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.VersionOption;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.View;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.TrialStart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import org.springframework.lang.Nullable;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The screen of measure and compare (quality plan 3.3, 3.8, quality P46), composed from the measurements, the cases,
 * the resource classes and what the quality gate reads; starting and cancelling a measurement are the measurements'.
 * Only the security decision is measured.
 *
 * <ul>
 * <li>The list: the model setting decisions are measured under, what a measurement can start with and what it would
 * take, the measurements that wait or run, and every measurement, newest first, with its misses and false stops; the
 * trials of the version screens (measurements on the latest sealed decisions) stand in the same list, with whether
 * the two versions kept their actions and the format errors, as they have no right answer.</li>
 * <li>One measurement: the metrics on the first answer and on the final action, over every case and over the cases of
 * each resource class, the default bundle and our cases apart, and the cases added after the version was made.</li>
 * <li>Two versions: the paired comparison the gate makes, metric by metric, the cases the two answer differently, the
 * misses grade by grade, and one case's answers side by side.</li>
 * </ul>
 */
public class PromptQualityMeasureScreen {

    /** The prompt that is measured. */
    static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;

    /**
     * The views of the screen in the order of its tab bar; this is the one place that lists them. A view added here
     * is a tab on every page of the screen, its page drawn by the script it names; its address needs a page mapping.
     */
    public static final List<View> VIEWS = List.of(
            new View("runs", "", "pqa.measure.tab.runs", PromptQualityScreens.Count.MEASUREMENTS, List.of(), null),
            new View("run", "/run", "pqa.measure.tab.run", null, List.of(), null),
            new View("compare", "/compare", "pqa.measure.tab.compare", null, List.of("trial"), null));

    /** The rows of a page of the list. */
    static final int PAGE_SIZE = 20;
    /** The furthest page of the list. */
    static final int MOST_PAGES = 50;
    /** The time one answer takes, as measured (plan 3.3: about 7 seconds), for the minutes a measurement takes. */
    static final double ANSWER_SECONDS = 7;
    /** The finished measurements a result can be chosen among, and the measurements looked through for a side. */
    static final int RECENT = 50;
    /** The metrics of a measurement in the order of the screen (plan 3.3); the time row comes last. */
    static final List<QualityMetric> METRICS = List.of(QualityMetric.MISS, QualityMetric.FALSE_STOP,
            QualityMetric.FRICTION, QualityMetric.OVER_BLOCK, QualityMetric.ACTION_HIT, QualityMetric.DEFERRAL,
            QualityMetric.CONSISTENCY, QualityMetric.CITATION_ACCURACY, QualityMetric.REASK, QualityMetric.MODEL_LESS);
    /** The four numbers on top of a result. */
    static final List<QualityMetric> HEADLINE = List.of(QualityMetric.MISS, QualityMetric.FALSE_STOP,
            QualityMetric.ACTION_HIT, QualityMetric.CITATION_ACCURACY);
    public static final String TIME = "TIME";

    public static final String NO_RUNNER = "NO_RUNNER";
    public static final String NOT_FOUND = "NOT_FOUND";
    public static final String NONE = "NONE";

    /** A request the screen refuses, with the code the screen names. */
    public static class RefusedException extends RuntimeException {

        private final String code;

        public RefusedException(String code, String message) {
            super(message);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private final Supplier<PromptQualityMeasurements> measurements;
    private final PromptQualityCases cases;
    private final Supplier<PromptQualityResourceClasses> classes;
    private final Supplier<QualityGateSource> gate;
    private final Supplier<PromptVersionConsole> console;
    private final Supplier<PromptVersionService> versions;
    private final Supplier<PromptVersionTrials> trials;
    private final ObjectMapper json;
    private final Clock clock;

    /**
     * @param measurements a supplier of null when this application cannot replay decisions
     * @param gate         what the quality gate reads; a supplier of null when there is none
     * @param console      what tells the versions and the one decisions run now
     * @param trials       the trials on the latest sealed decisions; a supplier of null when there are none
     */
    public PromptQualityMeasureScreen(@Nullable Supplier<PromptQualityMeasurements> measurements,
                                      PromptQualityCases cases,
                                      @Nullable Supplier<PromptQualityResourceClasses> classes,
                                      @Nullable Supplier<QualityGateSource> gate,
                                      @Nullable Supplier<PromptVersionConsole> console,
                                      @Nullable Supplier<PromptVersionService> versions,
                                      @Nullable Supplier<PromptVersionTrials> trials, ObjectMapper json,
                                      @Nullable Clock clock) {
        this.measurements = measurements != null ? measurements : () -> null;
        this.cases = Objects.requireNonNull(cases, "cases");
        this.classes = classes != null ? classes : () -> null;
        this.gate = gate != null ? gate : () -> null;
        this.console = console != null ? console : () -> null;
        this.versions = versions != null ? versions : () -> null;
        this.trials = trials != null ? trials : () -> null;
        this.json = Objects.requireNonNull(json, "json");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    // ----- the list and the start -----

    public RunsView runs(@Nullable String scope, int page) {
        String scopeName = PromptQualityCaseScreen.scopeOf(scope);
        int shown = Math.max(0, Math.min(page, MOST_PAGES));
        PromptQualityMeasurements runner = measurements.get();
        Choices choices = choices(scopeName);
        List<SetOption> sets = cases.publishedSets(scopeName, PROMPT, RECENT).stream()
                .map(set -> new SetOption(set.id(), set.version(), set.name(), set.caseCount(), set.publishedAt()))
                .toList();
        if (runner == null) {
            Page page0 = page(null, scopeName, shown);
            return new RunsView(scopeName, false, new Band(null, null, null, null, 0, 0),
                    new Start(choices.options(), choices.used(), sets, List.of(), 0, PromptVersionTrials.COUNTS, null),
                    List.of(), page0.rows(), shown, PAGE_SIZE, page0.total());
        }
        PromptQualityMeasurements.Settings settings = runner.settings();
        Band band = band();
        Integer first = defaultVersion(choices);
        EstimateView estimate = first != null ? estimate(scopeName, first, null, null) : null;
        List<Integer> repeats = new ArrayList<>();
        for (int runs = 1; runs <= PromptQualityMeasurements.MAX_REPEATS; runs++) {
            repeats.add(runs);
        }
        Start start = new Start(choices.options(), choices.used(), sets, List.copyOf(repeats), settings.repeats(),
                PromptVersionTrials.COUNTS, estimate);
        List<Running> running = runner.list(scopeName, PROMPT, 0, RECENT).stream()
                .filter(PromptQualityMeasureScreen::open).map(measure -> running(measure, settings)).toList();
        Page rows = page(runner, scopeName, shown);
        return new RunsView(scopeName, true, band, start, running, rows.rows(), shown, PAGE_SIZE, rows.total());
    }

    /** A page of the list and how many measurements there are in all. */
    private record Page(List<RunRow> rows, long total) {
    }

    /**
     * A page of the measurements on the labelled cases and of the trials, one list newest first: the newest of both up
     * to the end of the page, merged by when they were started.
     */
    private Page page(@Nullable PromptQualityMeasurements runner, String scope, int shown) {
        int end = (shown + 1) * PAGE_SIZE;
        PromptVersionTrials trial = trials.get();
        // A measurement or a trial, by when it was started.
        record Entry(Instant at, @Nullable PromptQualityMeasurements.Measure measure,
                     @Nullable PromptVersionTrials.Trial trial) {
        }
        List<Entry> entries = new ArrayList<>();
        if (runner != null) {
            runner.list(scope, PROMPT, 0, end).forEach(measure -> entries.add(new Entry(measure.createdAt(), measure,
                    null)));
        }
        if (trial != null) {
            trial.recent(scope, PROMPT, end).forEach(one -> entries.add(new Entry(one.createdAt(), null, one)));
        }
        entries.sort(Comparator.comparing(Entry::at, Comparator.nullsLast(Comparator.reverseOrder())));
        Map<Long, List<QualityCase>> read = new HashMap<>();
        List<RunRow> rows = new ArrayList<>();
        for (Entry entry : entries.subList(Math.min(entries.size(), shown * PAGE_SIZE), Math.min(entries.size(), end))) {
            rows.add(entry.measure() != null ? row(runner, entry.measure(), read) : trialRow(trial, entry.trial()));
        }
        long total = (runner != null ? runner.count(scope, PROMPT) : 0) + (trial != null ? trial.count(scope, PROMPT) : 0);
        return new Page(List.copyOf(rows), total);
    }

    /** A trial in the list: with no right answer, whether the two versions kept their actions and the format errors. */
    private static RunRow trialRow(PromptVersionTrials trial, PromptVersionTrials.Trial one) {
        boolean open = PromptVersionTrials.QUEUED.equals(one.status()) || PromptVersionTrials.RUNNING.equals(one.status());
        Double progress = open && one.replays() > 0 ? Math.min(1.0, (double) one.replayed() / one.replays()) : null;
        Integer pairs = null;
        Integer same = null;
        Long formatErrors = null;
        if (PromptVersionTrials.DONE.equals(one.status())) {
            Optional<PromptVersionTrials.Result> result = trial.result(one.id());
            if (result.isPresent()) {
                pairs = result.get().pairs();
                same = result.get().sameAction();
                formatErrors = result.get().candidate().formatErrors();
            }
        }
        return new RunRow("SEALED", one.id(), one.candidateName(), null, one.status(), one.createdAt(), one.createdBy(),
                null, null, progress, 0, null, null, one.referenceName(), one.requested(), pairs, same, formatErrors);
    }

    /** The model setting decisions are measured under now; empty values when nothing can be measured. */
    public Band band() {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return new Band(null, null, null, null, 0, 0);
        }
        Map<String, String> model = runner.modelSettings();
        return new Band(model.get("layer1.model"), model.get("layer2.model"), model.get("minimumAction.mode"),
                runner.settingsHash(), runner.settings().concurrency(), runner.settings().callLimit());
    }

    private static boolean open(PromptQualityMeasurements.Measure measure) {
        return PromptQualityMeasurements.QUEUED.equals(measure.status())
                || PromptQualityMeasurements.RUNNING.equals(measure.status());
    }

    /** The versions to choose from and the one decisions run now. */
    private record Choices(List<VersionOption> options, @Nullable String used) {
    }

    private Choices choices(String scope) {
        PromptVersionConsole versionConsole = console.get();
        if (versionConsole == null) {
            return new Choices(List.of(), null);
        }
        TrialStart start = versionConsole.trials(scope, PROMPT);
        return new Choices(start.versions().stream().map(row -> new VersionOption(row.number(), row.name(),
                row.state())).toList(), start.current());
    }

    /** The version a measurement starts with: the newest one decisions do not run, else the one they run. */
    @Nullable
    private static Integer defaultVersion(Choices choices) {
        return choices.options().stream().filter(option -> !"USED".equals(option.state())).findFirst()
                .or(() -> choices.options().stream().findFirst()).map(VersionOption::number).orElse(null);
    }

    private RunRow row(PromptQualityMeasurements runner, PromptQualityMeasurements.Measure measure,
                       Map<Long, List<QualityCase>> read) {
        Double progress = measure.plannedAnswers() > 0 ? Math.min(1.0, (double) measure.answered()
                / measure.plannedAnswers()) : null;
        Rate miss = null;
        Rate falseStop = null;
        int incomplete = 0;
        if (PromptQualityMeasurements.DONE.equals(measure.status())) {
            List<QualityCase> items = read.computeIfAbsent(measure.caseSetId(), this::caseSet);
            QualityScore score = QualityScorer.score(items, runner.answers(measure.id()),
                    QualityActionBasis.FIRST_ANSWER);
            miss = rate(score.rate(QualityMetric.MISS));
            falseStop = rate(score.rate(QualityMetric.FALSE_STOP));
            incomplete = score.incompleteAnswers();
        }
        return new RunRow("CASES", measure.id(), measure.versionName(), measure.modelSettingOrSettings(),
                measure.status(), measure.createdAt(), measure.createdBy(), measure.caseSetVersion(),
                measure.repeats(), progress, incomplete, miss, falseStop, null, null, null, null, null);
    }

    private List<QualityCase> caseSet(long setId) {
        return cases.published(setId).map(set -> cases.read(set).cases().cases()).orElse(List.of());
    }

    private Running running(PromptQualityMeasurements.Measure measure, PromptQualityMeasurements.Settings settings) {
        int left = Math.max(0, measure.plannedAnswers() - measure.answered());
        double seconds;
        Instant now = clock.instant();
        int taken = measure.answered() - measure.reusableAnswers();
        if (measure.startedAt() != null && taken > 0) {
            seconds = (double) Duration.between(measure.startedAt(), now).toMillis() / 1000 / taken * left;
        }
        else {
            seconds = left * ANSWER_SECONDS / Math.max(1, settings.concurrency());
        }
        return new Running(measure.id(), measure.versionName(), measure.caseSetVersion(), measure.repeats(),
                measure.status(), measure.answered(), measure.plannedAnswers(), measure.startedAt(),
                (int) Math.ceil(seconds / 60), measure.createdBy());
    }

    /**
     * What measuring the version on the bundle would take; a measurement that cannot start says why.
     *
     * @param caseSetId the published bundle, or null for the latest
     * @param repeats   the runs, or null for the set number
     */
    public EstimateView estimate(@Nullable String scope, int version, @Nullable Long caseSetId,
                                 @Nullable Integer repeats) {
        PromptQualityMeasurements runner = runner();
        try {
            PromptQualityMeasurements.Estimate estimate = runner.estimate(PromptQualityCaseScreen.scopeOf(scope), PROMPT,
                    version, caseSetId, repeats);
            int minutes = (int) Math.ceil(estimate.replays() * ANSWER_SECONDS
                    / Math.max(1, runner.settings().concurrency()) / 60);
            return new EstimateView(estimate.cases(), estimate.repeats(), estimate.answers(), estimate.reusable(),
                    estimate.replays(), estimate.minimumCalls(), estimate.maximumCalls(), estimate.callLimit(),
                    estimate.withinLimit(), minutes, estimate.withinLimit() ? null
                    : PromptQualityMeasurements.Refusal.CALL_LIMIT.name());
        }
        catch (PromptQualityMeasurements.RefusedException refused) {
            return new EstimateView(0, repeats != null ? repeats : runner.settings().repeats(), 0, 0, 0, 0, 0,
                    runner.settings().callLimit(), false, 0, refused.refusal().name());
        }
    }

    /** Starts measuring the version on the bundle; returns the measurement's id. */
    public long start(@Nullable String scope, @Nullable Integer version, @Nullable Long caseSetId,
                      @Nullable Integer repeats, String actor) {
        if (version == null) {
            throw new RefusedException(PromptQualityMeasurements.Refusal.VERSION.name(), "The version is required");
        }
        return runner().start(PromptQualityCaseScreen.scopeOf(scope), PROMPT, version, caseSetId, repeats,
                PromptQualityCaseScreen.actorOf(actor));
    }

    public boolean cancel(long id, String actor) {
        return runner().cancel(id, PromptQualityCaseScreen.actorOf(actor));
    }

    private PromptQualityMeasurements runner() {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            throw new RefusedException(NO_RUNNER, "This application cannot replay decisions to measure with");
        }
        return runner;
    }

    // ----- one measurement -----

    /**
     * The result of a measurement on the labelled cases; with no id, the latest finished one of the scope.
     *
     * @return empty when there is no such measurement
     */
    public Optional<RunView> run(@Nullable String scope, @Nullable Long id) {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return Optional.empty();
        }
        String scopeName = PromptQualityCaseScreen.scopeOf(scope);
        List<PromptQualityMeasurements.Measure> recent = runner.list(scopeName, PROMPT, 0, RECENT);
        List<Pick> picks = recent.stream().filter(measure -> PromptQualityMeasurements.DONE.equals(measure.status()))
                .map(measure -> new Pick(measure.id(), measure.versionName(), measure.caseSetVersion(),
                        measure.repeats(), measure.createdAt())).toList();
        Long chosen = id != null ? id : picks.stream().findFirst().map(Pick::id).orElse(null);
        Optional<PromptQualityMeasurements.Measure> found = chosen != null ? runner.find(chosen) : Optional.empty();
        if (found.isEmpty()) {
            return Optional.empty();
        }
        PromptQualityMeasurements.Measure measure = found.get();
        PromptQualityCases.ReadSet read = cases.read(cases.published(measure.caseSetId()).orElseThrow());
        List<QualityCase> items = read.cases().cases();
        List<QualityAnswer> answers = runner.answers(measure.id());
        Instant made = versionCreatedAt(measure);
        PromptQualityResourceClasses resourceClasses = classes.get();
        Optional<PromptQualityResourceClasses.MeasurementClasses> byClass = resourceClasses != null
                ? resourceClasses.measurement(measure.id()) : Optional.empty();
        List<QualityResourceClassScore> firstClasses = byClass.map(PromptQualityResourceClasses.MeasurementClasses::firstAnswer)
                .orElseGet(() -> QualityScorer.scoreByResourceClass(items, answers, QualityActionBasis.FIRST_ANSWER,
                        QualityCaseResources::of, QualityCaseResources.CLASSES));
        List<QualityResourceClassScore> finalClasses = byClass.map(PromptQualityResourceClasses.MeasurementClasses::finalAction)
                .orElseGet(() -> QualityScorer.scoreByResourceClass(items, answers, QualityActionBasis.FINAL,
                        QualityCaseResources::of, QualityCaseResources.CLASSES));
        Basis first = basis(items, answers, QualityActionBasis.FIRST_ANSWER, measure.repeats(), firstClasses, made);
        Basis last = basis(items, answers, QualityActionBasis.FINAL, measure.repeats(), finalClasses, made);
        int incomplete = (int) answers.stream().filter(QualityAnswer::measurementFailed).count();
        return Optional.of(new RunView(measure.id(), measure.versionName(), measure.versionNumber(),
                measure.caseSetVersion(), measure.repeats(), measure.modelSettingOrSettings(), measure.status(),
                measure.createdAt(), measure.createdBy(), answers.size(), incomplete, read.missing(), made, picks,
                first, last));
    }

    @Nullable
    private Instant versionCreatedAt(PromptQualityMeasurements.Measure measure) {
        PromptVersionService service = versions.get();
        return service != null ? service.find(measure.scope(), measure.prompt(), measure.versionNumber())
                .map(PromptVersionRecord::createdAt).orElse(null) : null;
    }

    private static Basis basis(List<QualityCase> items, List<QualityAnswer> answers, QualityActionBasis basis,
                               int repeats, List<QualityResourceClassScore> byClass, @Nullable Instant made) {
        QualityScore whole = QualityScorer.score(items, answers, basis);
        List<Metric> headline = HEADLINE.stream().map(metric -> metric(metric, whole.rate(metric), repeats)).toList();
        List<GradeMetrics> grades = new ArrayList<>();
        grades.add(new GradeMetrics("ALL", items.size(), whole.roots(), whole.answers(), metrics(whole, repeats)));
        for (QualityResourceClassScore score : byClass) {
            boolean shown = QualityCaseResources.CLASSES.contains(score.resourceClass()) || score.cases() > 0;
            if (shown) {
                grades.add(new GradeMetrics(score.resourceClass(), score.cases(),
                        score.stopRoots() + score.allowRoots(), score.scored() ? score.score().answers() : 0,
                        score.scored() ? metrics(score.score(), repeats) : null));
            }
        }
        Map<Boolean, QualityScore> origins = QualityScorer.scoreBy(items, answers, basis,
                item -> item.origin() == QualityCaseOrigin.CONTEXA);
        int contexaCases = (int) items.stream().filter(item -> item.origin() == QualityCaseOrigin.CONTEXA).count();
        Split split = new Split(new Part(contexaCases, missOf(origins.get(true), repeats)),
                new Part(items.size() - contexaCases, missOf(origins.get(false), repeats)));
        Metric overall = metric(QualityMetric.MISS, whole.rate(QualityMetric.MISS), repeats);
        List<QualityCase> later = made != null ? items.stream().filter(item -> item.arrivedAfter(made)).toList()
                : List.of();
        Metric laterMiss = missOf(later.isEmpty() ? null : QualityScorer.score(later, answers, basis), repeats);
        boolean worse = laterMiss.lo() != null && overall.value() != null && laterMiss.lo() > overall.value();
        return new Basis(headline, List.copyOf(grades), split, new Later(later.size(), laterMiss, overall, worse));
    }

    private static Metric missOf(@Nullable QualityScore score, int repeats) {
        return score != null ? metric(QualityMetric.MISS, score.rate(QualityMetric.MISS), repeats)
                : new Metric(QualityMetric.MISS.name(), 0L, 0L, null, null, null, 0, "NO_CASES", null, null, null,
                null);
    }

    static List<Metric> metrics(QualityScore score, int repeats) {
        List<Metric> metrics = new ArrayList<>();
        for (QualityMetric metric : METRICS) {
            metrics.add(metric(metric, score.rate(metric), repeats));
        }
        QualitySpread time = score.decisionMillis();
        QualitySpread tokens = score.answerTokens();
        metrics.add(new Metric(TIME, null, null, null, null, null, 0, time.count() == 0 ? "NO_CASES" : null,
                number(time.median()), number(time.ninetyFifth()), number(tokens.median()),
                number(tokens.ninetyFifth())));
        return List.copyOf(metrics);
    }

    static Metric metric(QualityMetric metric, @Nullable QualityRate rate, int repeats) {
        if (metric == QualityMetric.CONSISTENCY && repeats < 2) {
            return new Metric(metric.name(), null, null, null, null, null, 0, "ONE_RUN", null, null, null, null);
        }
        Rate value = rate(rate);
        if (value == null) {
            return new Metric(metric.name(), 0L, 0L, null, null, null, 0, null, null, null, null, null);
        }
        return new Metric(metric.name(), value.k(), value.n(), value.value(), value.lo(), value.hi(), value.roots(),
                null, null, null, null, null);
    }

    @Nullable
    static Rate rate(@Nullable QualityRate rate) {
        if (rate == null) {
            return null;
        }
        return rate.defined() ? new Rate(rate.events(), rate.trials(), number(rate.value()), number(rate.lower()),
                number(rate.upper()), rate.roots()) : new Rate(rate.events(), rate.trials(), null, null, null,
                rate.roots());
    }

    @Nullable
    private static Double number(double value) {
        return Double.isNaN(value) || Double.isInfinite(value) ? null : value;
    }

    // ----- two versions -----

    /** What the comparison of two versions reads: the gate's reading and the versions it is about. */
    private record Reading(String scope, List<VersionOption> options, @Nullable Integer candidate,
                           @Nullable Integer current, @Nullable QualityGateReading reading) {
    }

    private Reading reading(@Nullable String scope, @Nullable Integer candidate, @Nullable Integer current) {
        String scopeName = PromptQualityCaseScreen.scopeOf(scope);
        Choices choices = choices(scopeName);
        Integer currentNumber = current != null ? current
                : choices.used() != null ? PromptVersionNames.number(choices.used()).stream().boxed().findFirst()
                .orElse(null) : null;
        Integer candidateNumber = candidate;
        PromptQualityMeasurements runner = measurements.get();
        if (candidateNumber == null && runner != null) {
            candidateNumber = runner.list(scopeName, PROMPT, 0, RECENT).stream()
                    .filter(measure -> PromptQualityMeasurements.DONE.equals(measure.status()))
                    .map(PromptQualityMeasurements.Measure::versionNumber)
                    .filter(number -> !number.equals(currentNumber)).findFirst().orElse(null);
        }
        QualityGateSource source = gate.get();
        QualityGateReading reading = candidateNumber == null ? null
                : (source != null ? source : QualityGateSource.none()).read(scopeName, PROMPT,
                PromptVersionNames.name(candidateNumber),
                currentNumber != null ? PromptVersionNames.name(currentNumber) : null);
        return new Reading(scopeName, choices.options(), candidateNumber, currentNumber, reading);
    }

    private static boolean comparable(@Nullable QualityGateInput input) {
        return input != null && input.current() != null && input.candidate() != null
                && input.current().comparableWith(input.candidate());
    }

    public CompareView compare(@Nullable String scope, @Nullable Integer candidate, @Nullable Integer current) {
        Reading found = reading(scope, candidate, current);
        QualityGateReading reading = found.reading();
        if (reading == null) {
            return new CompareView(found.scope(), found.options(), null, found.current(), NONE, List.of(), null, null,
                    null, null, false, List.of(), null, new Splits(0, 0, 0, 0), List.of(), List.of(), List.of());
        }
        QualityGateInput input = reading.input();
        List<String> sides = reading.sides().stream().map(Enum::name).toList();
        String state = reading.state().name();
        if (!comparable(input)) {
            Side currentSide = input != null && input.current() != null
                    ? side(found, found.current(), input.current()) : null;
            Side candidateSide = input != null && input.candidate() != null
                    ? side(found, found.candidate(), input.candidate()) : null;
            return new CompareView(found.scope(), found.options(), found.candidate(), found.current(), state, sides,
                    reading.detail(), currentSide, candidateSide, null, false, List.of(), null,
                    new Splits(0, 0, 0, 0), List.of(), List.of(), List.of());
        }
        List<QualityCase> items = List.copyOf(input.cases());
        QualityMeasurement now = input.current();
        QualityMeasurement next = input.candidate();
        Map<QualityMetric, QualityComparison> comparisons = QualityComparator.compare(items, now, next,
                QualityActionBasis.FIRST_ANSWER, input.noise(), input.settings().significance());
        QualityScore before = QualityScorer.score(items, now.answers(), QualityActionBasis.FIRST_ANSWER);
        QualityScore after = QualityScorer.score(items, next.answers(), QualityActionBasis.FIRST_ANSWER);
        List<MetricCompare> metrics = new ArrayList<>();
        for (QualityMetric metric : METRICS) {
            QualityComparison comparison = comparisons.get(metric);
            metrics.add(new MetricCompare(metric.name(), comparison != null ? comparison.verdict().name()
                    : "UNDECIDABLE", comparison != null ? number(comparison.currentValue()) : null,
                    comparison != null ? number(comparison.candidateValue()) : null,
                    rate(before.rate(metric)), rate(after.rate(metric))));
        }
        TimeCompare time = new TimeCompare(number(before.decisionMillis().median()),
                number(after.decisionMillis().median()), number(before.answerTokens().median()),
                number(after.answerTokens().median()));
        QualityCaseChanges changes = QualityGateEvaluator.evaluate(input).changes();
        Map<String, QualityCase> byKey = new LinkedHashMap<>();
        items.forEach(item -> byKey.put(item.key(), item));
        Map<String, List<String>> nowActions = actions(now.answers(), QualityActionBasis.FIRST_ANSWER);
        Map<String, List<String>> nextActions = actions(next.answers(), QualityActionBasis.FIRST_ANSWER);
        List<SplitRow> rows = new ArrayList<>();
        addRows(rows, "NEW_MISS", changes.newlyMissed(), byKey, nowActions, nextActions);
        addRows(rows, "NEW_CATCH", changes.newlyCaught(), byKey, nowActions, nextActions);
        addRows(rows, "NEW_STOP", changes.newlyStopped(), byKey, nowActions, nextActions);
        addRows(rows, "NEW_PASS", changes.newlyReleased(), byKey, nowActions, nextActions);
        List<Noise> noise = new ArrayList<>();
        input.noise().widths().forEach((metric, width) -> noise.add(new Noise(metric.name(), width)));
        return new CompareView(found.scope(), found.options(), found.candidate(), found.current(), state, sides,
                reading.detail(), side(found, found.current(), now), side(found, found.candidate(), next),
                new Same(now.caseSetVersion(), now.modelSetting(), now.repeats()), true, List.copyOf(metrics), time,
                new Splits(changes.newlyMissed().size(), changes.newlyCaught().size(), changes.newlyStopped().size(),
                        changes.newlyReleased().size()), grades(found, items, now, next), List.copyOf(rows),
                List.copyOf(noise));
    }

    private static void addRows(List<SplitRow> rows, String split, List<String> keys, Map<String, QualityCase> byKey,
                                Map<String, List<String>> nowActions, Map<String, List<String>> nextActions) {
        for (String key : keys) {
            QualityCase item = byKey.get(key);
            rows.add(new SplitRow(key, item != null ? PromptQualityCaseScreen.name(item) : key, split,
                    nowActions.getOrDefault(key, List.of()), nextActions.getOrDefault(key, List.of())));
        }
    }

    /** The distinct actions each case was answered with, in the order of the runs. */
    private static Map<String, List<String>> actions(List<QualityAnswer> answers, QualityActionBasis basis) {
        Map<String, List<String>> actions = new HashMap<>();
        for (QualityAnswer answer : answers) {
            QualityAction action = basis.of(answer);
            if (answer.measurementFailed() || action == null) {
                continue;
            }
            List<String> given = actions.computeIfAbsent(answer.caseKey(), key -> new ArrayList<>());
            if (!given.contains(action.name())) {
                given.add(action.name());
            }
        }
        return actions;
    }

    /** The misses grade by grade: the counts of each version and the paired comparison of the grade. */
    private List<GradeCompare> grades(Reading found, List<QualityCase> items, QualityMeasurement now,
                                      QualityMeasurement next) {
        PromptQualityResourceClasses resourceClasses = classes.get();
        List<QualityResourceClassComparison> compared = resourceClasses != null && found.candidate() != null
                ? resourceClasses.comparison(found.scope(), PROMPT, PromptVersionNames.name(found.candidate()),
                found.current() != null ? PromptVersionNames.name(found.current()) : null).classes() : List.of();
        Map<String, QualityResourceClassScore> before = byClass(QualityScorer.scoreByResourceClass(items,
                now.answers(), QualityActionBasis.FIRST_ANSWER, QualityCaseResources::of, QualityCaseResources.CLASSES));
        Map<String, QualityResourceClassScore> after = byClass(QualityScorer.scoreByResourceClass(items,
                next.answers(), QualityActionBasis.FIRST_ANSWER, QualityCaseResources::of, QualityCaseResources.CLASSES));
        List<GradeCompare> grades = new ArrayList<>();
        for (QualityResourceClassComparison row : compared) {
            if (!QualityCaseResources.CLASSES.contains(row.resourceClass()) && row.cases() == 0) {
                continue;
            }
            QualityComparison miss = row.comparison(QualityMetric.MISS);
            grades.add(new GradeCompare(row.resourceClass(), row.cases(), row.compared(), row.changedCases(),
                    row.changes().newlyMissed().size(), row.compared() && miss != null ? miss.verdict().name() : null,
                    missRate(before.get(row.resourceClass())), missRate(after.get(row.resourceClass()))));
        }
        return List.copyOf(grades);
    }

    private static Map<String, QualityResourceClassScore> byClass(List<QualityResourceClassScore> scores) {
        Map<String, QualityResourceClassScore> map = new HashMap<>();
        scores.forEach(score -> map.put(score.resourceClass(), score));
        return map;
    }

    @Nullable
    private static Rate missRate(@Nullable QualityResourceClassScore score) {
        return score != null && score.scored() ? rate(score.score().rate(QualityMetric.MISS)) : null;
    }

    /** The side of a version: the finished measurement of the store the gate read for it, else a shipped one. */
    private Side side(Reading found, @Nullable Integer number, QualityMeasurement measurement) {
        return new Side(measurement.promptVersion(), number != null ? measureOf(found.scope(), number, measurement)
                : null);
    }

    @Nullable
    private Long measureOf(String scope, int number, QualityMeasurement measurement) {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return null;
        }
        return runner.recent(scope, PROMPT, number, RECENT).stream()
                .filter(measure -> PromptQualityMeasurements.DONE.equals(measure.status()))
                .filter(measure -> measure.caseSetVersion().equals(measurement.caseSetVersion()))
                .filter(measure -> measure.modelSettingOrSettings().equals(measurement.modelSetting()))
                .filter(measure -> measure.repeats() == measurement.repeats())
                .map(PromptQualityMeasurements.Measure::id).findFirst().orElse(null);
    }

    /**
     * One case's answers of the two versions compared, side by side: the actions of every run and the reason codes the
     * first run cited.
     *
     * @return empty when the two are not compared or the case is not theirs
     */
    public Optional<CaseAnswers> caseAnswers(@Nullable String scope, @Nullable Integer candidate,
                                             @Nullable Integer current, String key) {
        Reading found = reading(scope, candidate, current);
        QualityGateInput input = found.reading() != null ? found.reading().input() : null;
        if (!comparable(input) || key == null) {
            return Optional.empty();
        }
        Optional<QualityCase> item = input.cases().stream().filter(one -> one.key().equals(key.trim())).findFirst();
        if (item.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new CaseAnswers(item.get().key(), PromptQualityCaseScreen.name(item.get()),
                answerSide(found, found.current(), input.current(), item.get().key()),
                answerSide(found, found.candidate(), input.candidate(), item.get().key())));
    }

    private AnswerSide answerSide(Reading found, @Nullable Integer number, QualityMeasurement measurement,
                                  String key) {
        Long measureId = number != null ? measureOf(found.scope(), number, measurement) : null;
        PromptQualityMeasurements runner = measurements.get();
        if (measureId != null && runner != null) {
            List<PromptQualityMeasurements.CaseAnswer> answers = runner.caseAnswers(measureId, key);
            List<String> first = new ArrayList<>();
            List<String> last = new ArrayList<>();
            answers.forEach(answer -> {
                first.add(answer.measurementFailed() || answer.firstAction() == null ? null
                        : answer.firstAction().name());
                last.add(answer.measurementFailed() || answer.finalAction() == null ? null
                        : answer.finalAction().name());
            });
            List<Finding> findings = answers.stream().filter(answer -> !answer.measurementFailed()).findFirst()
                    .map(answer -> findings(answer.citationFindings())).orElse(List.of());
            return new AnswerSide(measurement.promptVersion(), measureId, first, last, findings);
        }
        List<String> first = new ArrayList<>();
        List<String> last = new ArrayList<>();
        measurement.answers().stream().filter(answer -> answer.caseKey().equals(key)).forEach(answer -> {
            first.add(answer.firstAction() != null && !answer.measurementFailed() ? answer.firstAction().name() : null);
            last.add(answer.finalAction() != null && !answer.measurementFailed() ? answer.finalAction().name() : null);
        });
        return new AnswerSide(measurement.promptVersion(), null, first, last, List.of());
    }

    /** The reason codes an answer cited, as kept with it: each with the fact it cites and what it came to. */
    List<Finding> findings(@Nullable String kept) {
        if (kept == null || kept.isBlank()) {
            return List.of();
        }
        try {
            JsonNode tree = json.readTree(kept);
            List<Finding> findings = new ArrayList<>();
            for (JsonNode one : tree) {
                findings.add(new Finding(QualityCaseInputSummary.text(one.path("code")),
                        QualityCaseInputSummary.text(one.path("fact")), QualityCaseInputSummary.text(one.path("outcome"))));
            }
            return List.copyOf(findings);
        }
        catch (IOException unreadable) {
            return List.of();
        }
    }
}
