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
package io.contexa.contexaiam.admin.promptquality.measure;

import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityComparator;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceClassComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceClassScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityResourceCoverage;
import io.contexa.contexacore.std.components.prompt.quality.QualityScorer;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseResources;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The prompt quality by resource class (quality P46). What is measured is a version of the prompt, not a resource: a
 * resource enters as the input of a case, so the cost of a measurement follows the cases however many resources are
 * protected. An average over every class would hide a version that decides worse on a sensitive resource alone, so
 * this reads the cases and the metrics class by class, with the class each case's input gives its decision rows
 * ({@link QualityCaseResources}).
 *
 * <ul>
 * <li>The coverage: the cases of a set by class (the roots that must be stopped and those that must be allowed) beside
 * the decisions the operation made in each class in a period, read from the hourly table of the console
 * ({@code ctxa_zt_stats_hourly}: the hours that start in the period, decisions only); a class the operation decides in
 * with no case, or with fewer roots on a side than a paired comparison of the class needs to be significant at the
 * level of the gate, is a gap. The decisions are those of the scope's tenant, and of every tenant for the platform
 * scope, as the trials, the causes and the report read them. With it the resources with the most cases and how many
 * resources the cases name.</li>
 * <li>A measurement: its metrics on both bases, class by class, each with its count, sample and 95% interval over
 * the roots; a class no case has is shown without a score.</li>
 * <li>Two versions: the paired comparison of the gate's reading, class by class on the first answers, with the cases
 * of each class the two answer differently. It is shown beside the gate and decides nothing: the gate reads the whole
 * set with its own conditions.</li>
 * </ul>
 * Nothing is written and no model is asked.
 */
public class PromptQualityResourceClasses {

    /** The period of the operation decisions when none is given. */
    static final Duration DEFAULT_PERIOD = Duration.ofDays(90);
    /** The longest period of the operation decisions. */
    static final Duration MAX_PERIOD = Duration.ofDays(400);
    /** How many resources the list of the most covered holds. */
    public static final int TOP_RESOURCES = 10;

    /**
     * The coverage of a case set.
     *
     * @param caseSetId      the published set read, or null for the cases the scope publishes now (the default set
     *                       and the confirmed cases kept in the scope)
     * @param caseSetVersion the version of the published set read, or null for the cases the scope publishes now
     * @param tenant         the tenant whose decisions are counted; null for every tenant (the platform scope)
     */
    public record Coverage(String scope, String prompt, @Nullable Long caseSetId, @Nullable String caseSetVersion,
                           Instant from, Instant to, @Nullable String tenant, QualityResourceCoverage coverage) {
    }

    /**
     * The metrics of a measurement by resource class.
     *
     * @param missingCases the cases of its set that cannot be read any more, and so are in no class
     */
    public record MeasurementClasses(PromptQualityMeasurements.Measure measure, List<String> missingCases,
                                     List<QualityResourceClassScore> firstAnswer,
                                     List<QualityResourceClassScore> finalAction) {
    }

    /**
     * The comparison of two versions by resource class, on the measurements the gate reads.
     *
     * @param state   the state of the measurements, as the gate reads them
     * @param sides   the versions the state is about
     * @param detail  why, in a code; null when there is nothing to add
     * @param basis   the action the rates are counted on: the first answers, as the gate reads them
     * @param classes the comparison of each class; empty when the two are not measured the same way
     */
    public record ComparisonClasses(String scope, String prompt, String candidate, @Nullable String current,
                                    QualityMeasurementState state, Set<QualityGateSide> sides,
                                    @Nullable String detail, QualityActionBasis basis,
                                    List<QualityResourceClassComparison> classes) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptQualityCases cases;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final Supplier<QualityGateSource> gate;
    private final Clock clock;

    /**
     * @param measurements the measurement runner; a supplier of null when this application cannot replay decisions
     * @param gate         what the quality gate reads the measurements from; a supplier of null when there is none
     */
    public PromptQualityResourceClasses(Supplier<JdbcTemplate> jdbc, PromptQualityCases cases,
                                        @Nullable Supplier<PromptQualityMeasurements> measurements,
                                        @Nullable Supplier<QualityGateSource> gate, @Nullable Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.measurements = measurements != null ? measurements : () -> null;
        this.gate = gate != null ? gate : () -> null;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * The coverage of a case set of the scope beside the decisions of the operation in the period.
     *
     * @param caseSetId the published set to read, or null for the cases the scope publishes now
     * @param from      the start of the period, or null for {@link #DEFAULT_PERIOD} before its end
     * @param to        the end of the period, or null for now; a later end is now
     * @throws PromptQualityCases.RefusedException when the prompt has no cases, or there is no such set in the scope
     * @throws IllegalArgumentException            when the period ends before it starts or is longer than
     *                                             {@link #MAX_PERIOD}
     */
    public Coverage coverage(@Nullable String scope, String prompt, @Nullable Long caseSetId, @Nullable Instant from,
                             @Nullable Instant to) {
        if (!PromptQualityCases.offeredFor(prompt)) {
            throw new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.PROMPT,
                    "Only the security decision has labelled cases");
        }
        String scopeName = scopeOf(scope);
        Instant now = clock.instant();
        Instant end = to == null || to.isAfter(now) ? now : to;
        Instant start = from != null ? from : end.minus(DEFAULT_PERIOD);
        if (!end.isAfter(start)) {
            throw new IllegalArgumentException("The period ends before it starts");
        }
        if (Duration.between(start, end).compareTo(MAX_PERIOD) > 0) {
            throw new IllegalArgumentException("The period is longer than " + MAX_PERIOD.toDays() + " days");
        }
        List<QualityCase> items;
        String setVersion = null;
        if (caseSetId != null) {
            PromptQualityCases.PublishedSet set = cases.published(caseSetId)
                    .filter(found -> found.scope().equals(scopeName) && found.prompt().equals(prompt))
                    .orElseThrow(() -> new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_FOUND,
                            "There is no case set " + caseSetId + " in the scope"));
            items = cases.read(set).cases().cases();
            setVersion = set.version();
        }
        else {
            items = new ArrayList<>(cases.defaultSet().cases());
            cases.list(scopeName, prompt).stream().filter(PromptQualityCases.Kept::confirmed)
                    .forEach(kept -> items.add(kept.item()));
        }
        String tenant = PromptVersionService.PLATFORM_SCOPE.equals(scopeName) ? null : scopeName;
        QualityResourceCoverage coverage = QualityResourceCoverage.of(items, QualityCaseResources::of,
                operationDecisions(tenant, start, end), QualityCaseResources.CLASSES,
                QualityResourceCoverage.minimumRoots(QualityGateSettings.defaults().significance()), TOP_RESOURCES);
        return new Coverage(scopeName, prompt, caseSetId, setVersion, start, end, tenant, coverage);
    }

    /**
     * The decisions of the operation by resource class in the hours that start in the period: first attempts that
     * reached an action, as the console counts them; the unclassified under the group of the unclassified cases.
     *
     * @param tenant the tenant whose decisions are counted, or null for every tenant
     */
    public Map<String, Long> operationDecisions(@Nullable String tenant, Instant from, Instant to) {
        List<Object> arguments = new ArrayList<>(List.of(Timestamp.from(from), Timestamp.from(to)));
        if (tenant != null) {
            arguments.add(tenant);
        }
        Map<String, Long> decisions = new LinkedHashMap<>();
        jdbc.get().query("select resource_class, sum(decision_count) from ctxa_zt_stats_hourly where bucket_start >= ?"
                + " and bucket_start < ? and final_action <> 'NO_DECISION'" + (tenant != null ? " and tenant_id = ?" : "")
                + " group by resource_class order by resource_class", rs -> {
            decisions.merge(QualityCaseResources.groupOfDecisions(rs.getString(1)), rs.getLong(2), Long::sum);
        }, arguments.toArray());
        return decisions;
    }

    /** The metrics of the measurement on both bases, class by class; empty when there is no such measurement. */
    public Optional<MeasurementClasses> measurement(long id) {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return Optional.empty();
        }
        Optional<PromptQualityMeasurements.Measure> found = runner.find(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        PromptQualityMeasurements.Measure measure = found.get();
        PromptQualityCases.ReadSet read = cases.read(cases.published(measure.caseSetId()).orElseThrow());
        List<QualityCase> items = read.cases().cases();
        List<QualityAnswer> answers = runner.answers(id);
        return Optional.of(new MeasurementClasses(measure, read.missing(),
                QualityScorer.scoreByResourceClass(items, answers, QualityActionBasis.FIRST_ANSWER,
                        QualityCaseResources::of, QualityCaseResources.CLASSES),
                QualityScorer.scoreByResourceClass(items, answers, QualityActionBasis.FINAL,
                        QualityCaseResources::of, QualityCaseResources.CLASSES)));
    }

    /**
     * The comparison of the candidate with the version in use class by class, on the measurements and the noise the
     * gate reads for them.
     *
     * @param candidate the version to be used ({@code v2.0})
     * @param current   the version the scope decides with now
     */
    public ComparisonClasses comparison(@Nullable String scope, String prompt, String candidate,
                                        @Nullable String current) {
        String scopeName = scopeOf(scope);
        QualityGateSource source = gate.get();
        QualityGateReading reading = (source != null ? source : QualityGateSource.none())
                .read(scopeName, prompt, candidate, current);
        QualityGateInput input = reading.input();
        List<QualityResourceClassComparison> classes = List.of();
        if (input != null && input.current() != null && input.candidate() != null
                && input.current().comparableWith(input.candidate())) {
            classes = QualityComparator.compareByResourceClass(input.cases(), input.current(), input.candidate(),
                    QualityActionBasis.FIRST_ANSWER, input.noise(), input.settings().significance(),
                    QualityCaseResources::of, QualityCaseResources.CLASSES);
        }
        return new ComparisonClasses(scopeName, prompt, candidate, current, reading.state(), reading.sides(),
                reading.detail(), QualityActionBasis.FIRST_ANSWER, classes);
    }

    private static String scopeOf(@Nullable String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }
}
