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
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCause;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseBasis;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.causes.PromptQualityCauses;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Pick;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Quality plan 3.5, 3.8: the view of the wrong cases and their causes under measure and compare. The wrong answers of a
 * measurement, and when asked the decisions administrators rated inadequate, each put down to one of the seven causes
 * by the rules of the causes ({@link PromptQualityCauses}): how many each cause has, where it is fixed, the conditions
 * it is computed under, the answers of each with the actions given and the right answer, and the change of a cause an
 * administrator makes. The answers a new prompt version fixes go beside the version editor.
 */
public class PromptQualityCauseScreen {

    static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    /** The period of the decisions rated inadequate shown with a measurement: the longest of the console's screens. */
    static final Duration DECISIONS_PERIOD = Duration.ofDays(90);
    /** The causes whose rule is computed only under a condition the screen states (plan 3.5). */
    static final Set<QualityCause> CONDITIONAL = Set.of(QualityCause.INPUT_SHORTAGE, QualityCause.UNSTABLE,
            QualityCause.FORMAT_AND_MODEL, QualityCause.INPUT_ERROR);
    private static final int RECENT = 50;
    private static final int PAGE = 500;

    /** Why the view or a change is refused. */
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

    /**
     * A cause as a tile of the view.
     *
     * @param notComputed the answers listed whose rule of this cause could not be computed
     * @param conditional whether the cause is computed only under a condition the view states
     */
    public record Tile(String cause, @Nullable String fix, int count, int notComputed, boolean conditional) {
    }

    /** A reason code an answer gave with the fact it cites. */
    public record Reason(String code, @Nullable String fact) {
    }

    /**
     * A wrong answer and its cause.
     *
     * @param source  MEASUREMENT or DECISION
     * @param given   the actions it gave on the basis it is wrong on
     * @param allowed the right answer of the case; empty for a decision, which has none
     * @param reasons the reason codes the answer cited, the model's reasons as a measurement keeps them
     */
    public record Row(long id, String source, String cause, @Nullable String ruleCause, boolean corrected,
                      @Nullable String caseKey, String name, @Nullable Integer run, List<String> given,
                      List<String> allowed, @Nullable String observationId, @Nullable String requestId,
                      List<Reason> reasons) {
    }

    /**
     * The causes of a measurement.
     *
     * @param decisions              the decisions rated inadequate in the period, classified, when asked
     * @param decisionsWithoutRecord the decisions rated inadequate whose record is gone
     * @param timeLimitMillis        the limit a timeout of the decisions is told by; 0 or less when not known
     */
    public record CausesView(long measureId, String version, int versionNumber, String caseSetVersion, int repeats,
                             Instant createdAt, List<Pick> picks, int answers, boolean withDecisions,
                             Instant decisionsFrom, Instant decisionsTo, int decisions, int decisionsWithoutRecord,
                             long timeLimitMillis, List<Tile> tiles, List<Row> rows) {
    }

    private final Supplier<PromptQualityMeasurements> measurements;
    private final Supplier<PromptQualityCauses> causes;
    private final PromptQualityCases cases;
    private final Supplier<JdbcTemplate> jdbc;
    private final ObjectMapper json;
    private final Clock clock;

    /**
     * @param measurements the measurement runner; a supplier of null when this application cannot measure
     * @param causes       the causes of the wrong answers; a supplier of null when they are not here
     */
    public PromptQualityCauseScreen(Supplier<PromptQualityMeasurements> measurements,
                                    Supplier<PromptQualityCauses> causes, PromptQualityCases cases,
                                    Supplier<JdbcTemplate> jdbc, ObjectMapper json, @Nullable Clock clock) {
        this.measurements = measurements != null ? measurements : () -> null;
        this.causes = causes != null ? causes : () -> null;
        this.cases = Objects.requireNonNull(cases, "cases");
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.json = Objects.requireNonNull(json, "json");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * The causes of the measurement, or of the latest finished one of the scope; with the decisions rated inadequate
     * in the last 90 days when asked.
     *
     * @return empty when there is no such measurement, or the causes are not here
     */
    public Optional<CausesView> causes(@Nullable String scope, @Nullable Long id, boolean withDecisions) {
        PromptQualityMeasurements runner = measurements.get();
        PromptQualityCauses kept = causes.get();
        if (runner == null || kept == null) {
            return Optional.empty();
        }
        String scopeName = PromptQualityCaseScreen.scopeOf(scope);
        List<Pick> picks = picks(runner, scopeName);
        Long chosen = id != null ? id : picks.stream().findFirst().map(Pick::id).orElse(null);
        Optional<PromptQualityMeasurements.Measure> found = chosen != null ? runner.find(chosen) : Optional.empty();
        if (found.isEmpty()) {
            return Optional.empty();
        }
        PromptQualityMeasurements.Measure measure = found.get();
        PromptQualityCauses.Summary measured = kept.ofMeasurement(measure.id()).orElseThrow();
        Instant to = clock.instant();
        Instant from = to.minus(DECISIONS_PERIOD);
        PromptQualityCauses.Summary decided = withDecisions ? kept.ofDecisions(scopeName, from, to) : null;
        List<PromptQualityCauses.Cause> all = new ArrayList<>(measured.causes());
        List<PromptQualityCauses.Count> counts = new ArrayList<>(measured.counts());
        if (decided != null) {
            all.addAll(decided.causes());
            counts.addAll(decided.counts());
        }
        Map<String, QualityCase> items = new HashMap<>();
        cases.published(measure.caseSetId()).ifPresent(set -> cases.read(set).cases().cases()
                .forEach(item -> items.put(item.key(), item)));
        Map<String, List<Reason>> reasons = reasons(measure.id());
        Map<String, String> requests = requests(decided != null ? decided.causes() : List.of());
        List<Row> rows = all.stream().map(cause -> row(cause, items, reasons, requests)).toList();
        return Optional.of(new CausesView(measure.id(), measure.versionName(), measure.versionNumber(),
                measure.caseSetVersion(), measure.repeats(), measure.createdAt(), picks, measured.causes().size(),
                withDecisions, from, to, decided != null ? decided.causes().size() : 0,
                decided != null ? decided.withoutRecord() : 0, kept.timeLimitMillis(), tiles(counts), rows));
    }

    /**
     * How many wrong answers the measurement has, or the latest finished one of the scope: the count beside the tab
     * of the view, read as it is kept; null when there is no measurement to count.
     */
    @Nullable
    public Long count(@Nullable String scope, @Nullable Long id) {
        PromptQualityMeasurements runner = measurements.get();
        PromptQualityCauses kept = causes.get();
        if (runner == null || kept == null) {
            return null;
        }
        Long chosen = id != null ? id : picks(runner, PromptQualityCaseScreen.scopeOf(scope)).stream().findFirst()
                .map(Pick::id).orElse(null);
        return chosen != null ? (long) kept.countOfMeasurement(chosen) : null;
    }

    /**
     * An administrator puts a wrong answer down to another cause.
     *
     * @throws RefusedException with the code of the causes' refusal, or UNAVAILABLE when the causes are not here
     */
    public Row correct(@Nullable String scope, long id, @Nullable String category, String actor) {
        PromptQualityCauses kept = causes.get();
        if (kept == null) {
            throw new RefusedException("UNAVAILABLE", "The causes of the wrong answers are not here");
        }
        QualityCause wanted = QualityCause.parse(category);
        try {
            PromptQualityCauses.Cause changed = kept.correct(PromptQualityCaseScreen.scopeOf(scope), id, wanted,
                    PromptQualityCaseScreen.actorOf(actor));
            return row(changed, Map.of(), Map.of(), Map.of());
        }
        catch (PromptQualityCauses.RefusedException refused) {
            throw new RefusedException(refused.refusal().name(), refused.getMessage());
        }
    }

    private static List<Pick> picks(PromptQualityMeasurements runner, String scope) {
        return runner.list(scope, PROMPT, 0, RECENT).stream()
                .filter(measure -> PromptQualityMeasurements.DONE.equals(measure.status()))
                .map(measure -> new Pick(measure.id(), measure.versionName(), measure.caseSetVersion(),
                        measure.repeats(), measure.createdAt())).toList();
    }

    /** The seven causes in the order of precedence, then the unclassified ones when there are some. */
    private static List<Tile> tiles(List<PromptQualityCauses.Count> counts) {
        Map<QualityCause, int[]> tally = new EnumMap<>(QualityCause.class);
        for (PromptQualityCauses.Count count : counts) {
            int[] numbers = tally.computeIfAbsent(count.cause(), key -> new int[2]);
            numbers[0] += count.count();
            numbers[1] += count.notComputed();
        }
        List<Tile> tiles = new ArrayList<>();
        for (QualityCause cause : QualityCause.RULED) {
            int[] numbers = tally.getOrDefault(cause, new int[2]);
            tiles.add(new Tile(cause.name(), cause.fix() != null ? cause.fix().name() : null, numbers[0], numbers[1],
                    CONDITIONAL.contains(cause)));
        }
        int[] unclassified = tally.getOrDefault(QualityCause.UNCLASSIFIED, new int[2]);
        if (unclassified[0] > 0) {
            tiles.add(new Tile(QualityCause.UNCLASSIFIED.name(), null, unclassified[0], unclassified[1], false));
        }
        return List.copyOf(tiles);
    }

    private static Row row(PromptQualityCauses.Cause cause, Map<String, QualityCase> items,
                           Map<String, List<Reason>> reasons, Map<String, String> requests) {
        Map<String, Object> actions = cause.actions();
        boolean measured = cause.source() == PromptQualityCauses.Source.MEASUREMENT;
        Set<String> given = new LinkedHashSet<>();
        if (measured) {
            QualityCauseBasis basis = cause.basis() != null ? cause.basis() : QualityCauseBasis.BOTH;
            if (basis.firstAnswer()) {
                add(given, actions.get("first"));
            }
            if (basis.finalAction()) {
                add(given, actions.get("final"));
            }
        }
        else {
            add(given, actions.get("model"));
            add(given, actions.get("final"));
        }
        List<String> allowed = new ArrayList<>();
        if (actions.get("allowed") instanceof List<?> list) {
            list.forEach(action -> add(allowed, action));
        }
        QualityCase item = cause.caseKey() != null ? items.get(cause.caseKey()) : null;
        String name = measured ? (item != null ? MeasuredQualityGateSource.caseName(item) : String.valueOf(cause.caseKey()))
                : requests.getOrDefault(String.valueOf(cause.observationId()), String.valueOf(cause.requestId()));
        return new Row(cause.id(), cause.source().name(), cause.category().name(),
                cause.ruleCategory() != null ? cause.ruleCategory().name() : null, cause.corrected(), cause.caseKey(),
                name, cause.run(), List.copyOf(given), List.copyOf(allowed), cause.observationId(), cause.requestId(),
                measured ? reasons.getOrDefault(cause.caseKey() + "#" + cause.run(), List.of()) : List.of());
    }

    private static void add(Collection<String> into, @Nullable Object action) {
        if (action != null && !action.toString().isBlank() && !"null".equals(action.toString())) {
            into.add(action.toString());
        }
    }

    /** The reason codes each answer of the measurement cited, with their facts, by case and run. */
    private Map<String, List<Reason>> reasons(long measureId) {
        Map<String, List<Reason>> reasons = new HashMap<>();
        jdbc.get().query("select case_key, run_number, citation_findings from ctxa_prompt_version_measure_answer"
                + " where measure_id = ?", rs -> {
            String findings = rs.getString("citation_findings");
            if (findings == null || findings.isBlank()) {
                return;
            }
            List<Reason> cited = new ArrayList<>();
            try {
                JsonNode kept = json.readTree(findings);
                kept.forEach(finding -> {
                    String code = finding.path("code").asText("");
                    if (!code.isBlank()) {
                        String fact = finding.path("fact").asText("");
                        cited.add(new Reason(code, fact.isBlank() ? null : fact));
                    }
                });
            }
            catch (Exception unreadable) {
                // An answer whose findings do not read names no reason; its cause stands as it is.
                return;
            }
            reasons.put(rs.getString("case_key") + "#" + rs.getInt("run_number"), List.copyOf(cited));
        }, measureId);
        return reasons;
    }

    /** The request of each decision rated inadequate, as its method and path, by its decision record. */
    private Map<String, String> requests(List<PromptQualityCauses.Cause> decided) {
        List<String> observations = decided.stream().map(PromptQualityCauses.Cause::observationId)
                .filter(Objects::nonNull).distinct().toList();
        Map<String, String> requests = new HashMap<>();
        for (int start = 0; start < observations.size(); start += PAGE) {
            List<String> page = observations.subList(start, Math.min(observations.size(), start + PAGE));
            jdbc.get().query("select observation_id, http_method, request_path, request_id from"
                    + " ctxa_ai_security_decision_observation where observation_id in ("
                    + String.join(", ", Collections.nCopies(page.size(), "?")) + ")", rs -> {
                String asked = ((rs.getString("http_method") != null ? rs.getString("http_method") + " " : "")
                        + (rs.getString("request_path") != null ? rs.getString("request_path") : "")).trim();
                requests.put(rs.getString("observation_id"), asked.isEmpty() ? String.valueOf(rs.getString(
                        "request_id")) : asked);
            }, page.toArray());
        }
        return requests;
    }
}
