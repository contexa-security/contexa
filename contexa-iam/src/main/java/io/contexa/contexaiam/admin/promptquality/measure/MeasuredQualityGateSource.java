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

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityNoise;
import io.contexa.contexacore.std.components.prompt.quality.QualityShippedMeasurements;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityCaseName;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityDetails;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityProgress;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The measurements the quality gate reads (plan 3.4), from the store of the measurements: the latest case set
 * published in the scope, and for the candidate and the version in use the measurements finished on it.
 *
 * <ul>
 * <li>A measurement is fresh when it ran under the server settings that change an answer as this server runs them
 * now, and stale otherwise (the model setting changed). The two compared are a fresh one of each, taken the same way
 * (the same case set version, model setting and runs) when there are such.</li>
 * <li>The width inside which two versions count as the same is the difference of two measurements of one version
 * taken the same way, of the version in use first, else of the candidate, when their answers are their own: a
 * measurement that used the other's answers again shows no noise and is not read for it. Without such a pair the
 * width is not known.</li>
 * <li>A Contexa version measured before the release, as the product ships it, is measured here when its content, the
 * case set version and the settings are the same as here.</li>
 * <li>Missing: the candidate has no measurement, or the version in use has none and none waits. Stale: one of the two
 * has stale measurements only. The first measurement of the version in use waits: it has none, and one is queued or
 * running. Cannot be measured: this installation has no replay of decisions to measure with.</li>
 * </ul>
 * The detail names a measurement that waits or runs ({@link #MEASURING}), a scope with no published case set
 * ({@link #NO_CASE_SET}), a shipped measurement read ({@link #SHIPPED}), or why nothing can be measured.
 */
public class MeasuredQualityGateSource implements QualityGateSource {

    /** No measurement runner: the decision pipeline the replay needs is not in this application. */
    public static final String NO_MEASUREMENT_RUNNER = "NO_MEASUREMENT_RUNNER";
    /** A measurement of the version that is missing, stale or waited for is queued or running. */
    public static final String MEASURING = "MEASURING";
    /** Nothing is published in the scope yet; a measurement publishes the default set first. */
    public static final String NO_CASE_SET = "NO_CASE_SET";
    /** A measurement Contexa shipped with the product was read. */
    public static final String SHIPPED = "SHIPPED_MEASUREMENT";
    /** Where a model setting names the models that answered, and how it names models it does not know. */
    private static final String MODELS = "models=";
    private static final String UNKNOWN_MODELS = "unknown";
    /** How many of the latest measurements of a version are looked at. */
    static final int RECENT = 50;

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final PromptQualityCases cases;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final QualityShippedMeasurements shipped;

    /**
     * @param measurements the measurement runner; a supplier of null when this application cannot replay decisions
     * @param shipped      the measurements the product ships; none when null
     */
    public MeasuredQualityGateSource(Supplier<JdbcTemplate> jdbc, PromptVersionService versions,
                                     PromptQualityCases cases, Supplier<PromptQualityMeasurements> measurements,
                                     QualityShippedMeasurements shipped) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.measurements = measurements != null ? measurements : () -> null;
        this.shipped = shipped != null ? shipped : QualityShippedMeasurements.none();
    }

    /** A measurement as the gate reads it: from a row of the store, or shipped; its answers read when needed. */
    private static final class Taken {

        private final PromptQualityMeasurements.Measure row;
        private final QualityMeasurement shippedMeasurement;
        private final QualityMeasurement shape;
        private QualityMeasurement read;

        private Taken(PromptQualityMeasurements.Measure row, String versionName) {
            this.row = row;
            this.shippedMeasurement = null;
            this.shape = new QualityMeasurement(versionName, row.modelSettingOrSettings(), row.caseSetVersion(),
                    row.repeats(), List.of());
        }

        private Taken(QualityMeasurement shippedMeasurement) {
            this.row = null;
            this.shippedMeasurement = shippedMeasurement;
            this.shape = shippedMeasurement;
        }

        boolean comparableWith(Taken other) {
            return other != null && shape.comparableWith(other.shape);
        }

        QualityMeasurement measurement(PromptQualityMeasurements runner) {
            if (read == null) {
                read = shippedMeasurement != null ? shippedMeasurement
                        : new QualityMeasurement(shape.promptVersion(), shape.modelSetting(), shape.caseSetVersion(),
                        shape.repeats(), runner.answers(row.id()));
            }
            return read;
        }
    }

    /**
     * What one version has on the case set: its fresh and stale measurements, newest first, and the newest one that
     * waits or runs under the settings of now (null when none does).
     */
    private record Side(PromptVersionRecord version, List<Taken> fresh, List<Taken> stale,
                        PromptQualityMeasurements.Measure waiting) {

        boolean open() {
            return waiting != null;
        }

        boolean none() {
            return fresh.isEmpty() && stale.isEmpty();
        }

        boolean staleOnly() {
            return fresh.isEmpty() && !stale.isEmpty();
        }

        List<Taken> taken() {
            List<Taken> all = new ArrayList<>(fresh);
            all.addAll(stale);
            return all;
        }
    }

    @Override
    public QualityGateReading read(String scope, String prompt, String candidate, String current) {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return QualityGateReading.unmeasurable(NO_MEASUREMENT_RUNNER);
        }
        if (!PromptQualityCases.offeredFor(prompt)) {
            return QualityGateReading.unmeasurable(QualityGateSource.NO_SOURCE);
        }
        String scopeName = scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
        Optional<PromptQualityCases.PublishedSet> set = cases.latestPublished(scopeName, prompt);
        String setVersion = set.map(PromptQualityCases.PublishedSet::version)
                .orElseGet(() -> cases.defaultSet().version());
        String now = runner.settingsHash();
        Side candidateSide = side(runner, scopeName, prompt, candidate, set.orElse(null), setVersion, now);
        Side currentSide = current != null
                ? side(runner, scopeName, prompt, current, set.orElse(null), setVersion, now) : null;

        Taken[] pair = pair(candidateSide, currentSide);
        QualityGateInput input = null;
        if (pair[0] != null || pair[1] != null) {
            List<QualityCase> items = set.isPresent() ? cases.read(set.get()).cases().cases()
                    : cases.defaultSet().cases();
            QualityMeasurement compared = pair[0] != null ? pair[0].measurement(runner) : null;
            QualityMeasurement inUse = pair[1] != null ? pair[1].measurement(runner) : null;
            input = new QualityGateInput(items, inUse, compared, noise(runner, items, currentSide, candidateSide,
                    pair), QualityGateSettings.defaults(),
                    candidateSide.version() != null ? candidateSide.version().createdAt() : null);
        }
        boolean shippedRead = (pair[0] != null && pair[0].row == null) || (pair[1] != null && pair[1].row == null);

        Set<QualityGateSide> missing = EnumSet.noneOf(QualityGateSide.class);
        if (candidateSide.none()) {
            missing.add(QualityGateSide.CANDIDATE);
        }
        if (currentSide != null && currentSide.none() && !currentSide.open()) {
            missing.add(QualityGateSide.CURRENT);
        }
        if (!missing.isEmpty()) {
            String detail = candidateSide.none() && candidateSide.open() ? MEASURING
                    : set.isEmpty() ? NO_CASE_SET : null;
            return new QualityGateReading(QualityMeasurementState.MISSING, missing, input, detail);
        }
        Set<QualityGateSide> stale = EnumSet.noneOf(QualityGateSide.class);
        boolean staleMeasuring = false;
        if (candidateSide.staleOnly()) {
            stale.add(QualityGateSide.CANDIDATE);
            staleMeasuring = candidateSide.open();
        }
        if (currentSide != null && currentSide.staleOnly()) {
            stale.add(QualityGateSide.CURRENT);
            staleMeasuring = staleMeasuring || currentSide.open();
        }
        if (!stale.isEmpty()) {
            return new QualityGateReading(QualityMeasurementState.STALE, stale, input,
                    staleMeasuring ? MEASURING : null);
        }
        if (currentSide != null && currentSide.none()) {
            // The version in use has no measurement and one waits or runs: right after an upgrade, until it is done.
            return new QualityGateReading(QualityMeasurementState.BASELINE_PENDING, Set.of(QualityGateSide.CURRENT),
                    input, MEASURING);
        }
        return new QualityGateReading(QualityMeasurementState.MEASURED, Set.of(), input, shippedRead ? SHIPPED : null);
    }

    private Side side(PromptQualityMeasurements runner, String scope, String prompt, String name,
                      PromptQualityCases.PublishedSet set, String setVersion, String now) {
        OptionalInt number = PromptVersionNames.number(name);
        PromptVersionRecord record = number.isPresent()
                ? versions.find(scope, prompt, number.getAsInt()).orElse(null) : null;
        if (record == null) {
            return new Side(null, List.of(), List.of(), null);
        }
        List<Taken> fresh = new ArrayList<>();
        List<Taken> stale = new ArrayList<>();
        PromptQualityMeasurements.Measure waiting = null;
        if (set != null) {
            for (PromptQualityMeasurements.Measure row : runner.recent(scope, prompt, record.number(), RECENT)) {
                if (row.caseSetId() != set.id() || !row.versionContentHash().equals(record.contentHash())) {
                    continue;
                }
                boolean sameSettings = row.settingsHash().equals(now);
                if (PromptQualityMeasurements.QUEUED.equals(row.status())
                        || PromptQualityMeasurements.RUNNING.equals(row.status())) {
                    if (sameSettings && waiting == null) {
                        waiting = row;
                    }
                }
                else if (PromptQualityMeasurements.DONE.equals(row.status())) {
                    (sameSettings ? fresh : stale).add(new Taken(row, record.name()));
                }
            }
        }
        if (fresh.isEmpty()) {
            shipped.find(prompt, record.contentHash(), setVersion, now)
                    .ifPresent(found -> fresh.add(new Taken(found.measurement(record.name()))));
        }
        return new Side(record, List.copyOf(fresh), List.copyOf(stale), waiting);
    }

    /**
     * Quality plan 3.4 and the approved confirmation: what it names beside the verdict, from the reads the verdict
     * rests on: the version of the case set the measurements are taken on, the models of the measurements compared
     * (else of the server now), the models of a stale measurement and of the server now, the measurement of the
     * version in use that waits or runs (else of the candidate), and the names of the cases asked for. The verdict
     * itself is the gate's; nothing here changes it.
     *
     * @return the details, or null when this application cannot measure or the prompt has no cases
     */
    public QualityDetails details(String scope, String prompt, String candidate, String current,
                                  Collection<String> caseKeys) {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null || !PromptQualityCases.offeredFor(prompt)) {
            return null;
        }
        String scopeName = scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
        Optional<PromptQualityCases.PublishedSet> set = cases.latestPublished(scopeName, prompt);
        String setVersion = set.map(PromptQualityCases.PublishedSet::version)
                .orElseGet(() -> cases.defaultSet().version());
        String now = runner.settingsHash();
        Side candidateSide = side(runner, scopeName, prompt, candidate, set.orElse(null), setVersion, now);
        Side currentSide = current != null
                ? side(runner, scopeName, prompt, current, set.orElse(null), setVersion, now) : null;
        Taken[] pair = pair(candidateSide, currentSide);
        Taken compared = pair[0] != null ? pair[0] : pair[1];
        String modelsNow = runner.models().isEmpty() ? null : String.join(", ", runner.models());
        Side stale = currentSide != null && currentSide.staleOnly() ? currentSide
                : candidateSide.staleOnly() ? candidateSide : null;
        Side waiting = currentSide != null && currentSide.open() ? currentSide
                : candidateSide.open() ? candidateSide : null;
        QualityProgress measuring = waiting != null ? new QualityProgress(waiting.version().name(),
                waiting.waiting().answered(), waiting.waiting().plannedAnswers()) : null;
        return new QualityDetails(setVersion, compared != null ? models(compared.shape.modelSetting()) : modelsNow,
                stale != null ? models(stale.stale().get(0).shape.modelSetting()) : null, modelsNow, measuring,
                caseNames(set.orElse(null), caseKeys));
    }

    /** The models a model setting names (settings=<hash>;models=<names>); null when they are not known. */
    static String models(String modelSetting) {
        if (modelSetting == null) {
            return null;
        }
        int at = modelSetting.indexOf(MODELS);
        if (at < 0) {
            return null;
        }
        int end = modelSetting.indexOf(';', at);
        String models = modelSetting.substring(at + MODELS.length(), end < 0 ? modelSetting.length() : end).trim();
        return models.isEmpty() || UNKNOWN_MODELS.equals(models) ? null : models.replace(",", ", ");
    }

    /** The names of the cases asked for, as the cases of the set the measurements are taken on have them. */
    private List<QualityCaseName> caseNames(PromptQualityCases.PublishedSet set, Collection<String> keys) {
        if (keys == null || keys.isEmpty()) {
            return List.of();
        }
        List<QualityCase> items = set != null ? cases.read(set).cases().cases() : cases.defaultSet().cases();
        Map<String, QualityCase> byKey = new HashMap<>();
        items.forEach(item -> byKey.put(item.key(), item));
        List<QualityCaseName> names = new ArrayList<>();
        for (String key : keys) {
            QualityCase item = byKey.get(key);
            names.add(new QualityCaseName(key, item != null ? caseName(item) : key));
        }
        return List.copyOf(names);
    }

    /**
     * The name of a case as the screens give it (quality plan 3.2): what the request asked, its method and path, and
     * the key; the key alone when the input names no request.
     */
    static String caseName(QualityCase item) {
        JsonNode resource = item.input().canonicalContext().path("resource");
        JsonNode facts = item.input().requestFacts();
        String method = text(resource.path("httpMethod"));
        method = method != null ? method : text(facts == null ? null : facts.path("httpMethod"));
        String path = text(resource.path("requestPath"));
        path = path != null ? path : text(facts == null ? null : facts.path("requestPath"));
        String asked = ((method != null ? method + " " : "") + (path != null ? path : "")).trim();
        return asked.isEmpty() ? item.key() : asked + " (" + item.key() + ")";
    }

    private static String text(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText().trim();
        return value.isEmpty() ? null : value;
    }

    /**
     * The candidate's and the version in use's measurements to compare: the first pair taken the same way, the fresh
     * ones first and the newest first, else the first of each.
     */
    private static Taken[] pair(Side candidate, Side current) {
        List<Taken> candidates = candidate.taken();
        List<Taken> inUse = current != null ? current.taken() : List.of();
        for (Taken one : candidates) {
            for (Taken other : inUse) {
                if (one.comparableWith(other)) {
                    return new Taken[] {one, other};
                }
            }
        }
        return new Taken[] {candidates.isEmpty() ? null : candidates.get(0), inUse.isEmpty() ? null : inUse.get(0)};
    }

    /**
     * The noise: the difference of two fresh measurements of one version taken as the compared ones were, whose
     * answers are their own; of the version in use first, else of the candidate. Unknown without such a pair.
     */
    private QualityNoise noise(PromptQualityMeasurements runner, List<QualityCase> items, Side current,
                               Side candidate, Taken[] pair) {
        Taken reference = pair[0] != null ? pair[0] : pair[1];
        for (Side side : current != null ? List.of(current, candidate) : List.of(candidate)) {
            List<Taken> rows = side.fresh().stream().filter(taken -> taken.row != null).toList();
            for (int first = 0; first < rows.size(); first++) {
                for (int second = first + 1; second < rows.size(); second++) {
                    Taken one = rows.get(first);
                    Taken other = rows.get(second);
                    if (one.comparableWith(other) && one.comparableWith(reference)
                            && independent(one.row.id(), other.row.id())) {
                        return QualityNoise.between(items, one.measurement(runner), other.measurement(runner),
                                QualityActionBasis.FIRST_ANSWER);
                    }
                }
            }
        }
        return null;
    }

    /** Whether no answer of the one measurement is an answer of the other used again. */
    private boolean independent(long one, long other) {
        Integer shared = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_measure_answer a where"
                + " a.measure_id = ? and coalesce(a.reused_from_answer_id, a.id) in (select coalesce("
                + "b.reused_from_answer_id, b.id) from ctxa_prompt_version_measure_answer b where b.measure_id = ?)",
                Integer.class, one, other);
        return shared == null || shared == 0;
    }
}
