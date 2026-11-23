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
package io.contexa.contexaiam.admin.promptquality.causes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCause;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseCheck;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseCitations;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseClassifier;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseDecision;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseFix;
import io.contexa.contexacore.std.components.prompt.quality.QualityCauseResult;
import io.contexa.contexacore.verification.inspection.SourceTruthCheck;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The causes of the wrong answers (quality plan 3.5): the wrong answers of a measurement and the decisions an
 * administrator rated inadequate are put down to a cause by the deterministic rules of {@link QualityCauseClassifier}
 * and kept in {@code ctxa_prompt_version_case_cause}, one row per answer and one per decision; an administrator may put
 * one down to another cause.
 *
 * <p>When: a measurement is classified when it is done ({@link PromptQualityMeasurements#whenDone}), and again whenever
 * its causes are read, which finds a measurement done before or one whose classification failed; its answers do not
 * change once it is done. The decisions are classified whenever their causes are read, since the evidence audit may
 * inspect a seal after the evaluation. Classifying again with the same records writes nothing; a rule that now comes to
 * another result writes the new rule category and basis, and the category too unless an administrator corrected it: a
 * correction is never overwritten. A correction keeps who made it, when, and the category it replaced.</p>
 *
 * <p>A decision's row belongs to the scope of its tenant (the platform's when it has none); the platform scope reads
 * every tenant's, as the trials do. Nothing here asks a model.</p>
 */
public class PromptQualityCauses {

    private static final Logger log = LoggerFactory.getLogger(PromptQualityCauses.class);

    /** Who classified a row the rules wrote. */
    public static final String RULES = "contexa-rules";
    private static final int PAGE = 500;

    /** Where the wrong answer comes from. */
    public enum Source {
        /** An answer of a measurement. */
        MEASUREMENT,
        /** A decision an administrator rated inadequate. */
        DECISION
    }

    /** Why a correction is refused. */
    public enum Refusal {
        /** There is no such cause in the scope. */
        NOT_FOUND,
        /** The category is none of the seven causes. */
        CATEGORY,
        /** Only a decision can be put down to an input error. */
        DECISIONS_ONLY
    }

    /** A correction that is refused, and why. */
    public static class RefusedException extends RuntimeException {

        private final Refusal refusal;

        public RefusedException(Refusal refusal, String message) {
            super(message);
            this.refusal = refusal;
        }

        public Refusal refusal() {
            return refusal;
        }
    }

    /**
     * A wrong answer and its cause, as its row keeps it.
     *
     * @param category         the cause it is put down to: the rule's, or the administrator's correction
     * @param ruleCategory     the cause the rules put it down to
     * @param basis            which action of a measured answer is wrong; null for a decision
     * @param checks           what each rule found, in the order of precedence
     * @param actions          the actions the rules read: of a measured answer the first, the model's, the final and
     *                         the allowed ones; of a decision the model's proposal and the final one
     * @param previousCategory the category the latest correction replaced, or null
     */
    public record Cause(long id, String scope, String prompt, Source source, @Nullable Long measureId,
                        @Nullable String caseKey, @Nullable Integer run, @Nullable String requestId,
                        @Nullable String observationId, QualityCause category, @Nullable QualityCause ruleCategory,
                        @Nullable QualityCauseBasis basis, List<QualityCauseCheck> checks, Map<String, Object> actions,
                        String classifiedBy, Instant classifiedAt, @Nullable String correctedBy,
                        @Nullable Instant correctedAt, @Nullable QualityCause previousCategory) {

        public boolean corrected() {
            return correctedBy != null;
        }

        /** Where it is fixed; null while it is unclassified. */
        @Nullable
        public QualityCauseFix fix() {
            return category.fix();
        }
    }

    /**
     * How many wrong answers are put down to a cause, and for how many of them the cause's rule could not be computed.
     *
     * @param notComputed the listed answers whose rule of this cause could not be computed (plan 3.5: the screen
     *                    states the conditions a cause is computed under)
     */
    public record Count(QualityCause cause, @Nullable QualityCauseFix fix, int count, int notComputed) {
    }

    /**
     * The causes of the wrong answers of a measurement, or of the decisions rated inadequate in a period.
     *
     * @param counts        each cause in the order of precedence, then the unclassified ones
     * @param causes        the wrong answers with their causes
     * @param forNewVersion the ones whose cause is fixed by a new version of the prompt, to show beside the editor
     * @param withoutRecord the decisions rated inadequate whose decision record is gone, which cannot be classified
     */
    public record Summary(Source source, @Nullable Long measureId, List<Count> counts, List<Cause> causes,
                          List<Cause> forNewVersion, int withoutRecord) {
    }

    private record MeasureRow(long id, String scope, String prompt, long caseSetId, String status) {
    }

    private record Evaluation(String observationId, String requestId, String reason) {
    }

    private record Classified(List<String> observations, int withoutRecord) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptQualityCases cases;
    private final ObjectMapper json;
    private final LongSupplier timeLimitMillis;
    private final Clock clock;

    /**
     * @param timeLimitMillis the time limit of a first-layer model call of the decisions (plan 3.5: the limit of the
     *                        decisions, not the replay's); 0 or less when it is not known
     */
    public PromptQualityCauses(Supplier<JdbcTemplate> jdbc, PromptQualityCases cases, ObjectMapper json,
                               LongSupplier timeLimitMillis, @Nullable Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.json = Objects.requireNonNull(json, "json");
        this.timeLimitMillis = Objects.requireNonNull(timeLimitMillis, "timeLimitMillis");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** The time limit of a first-layer model call the server's settings give (the decisions' own limit). */
    public static long decisionCallLimitMillis(@Nullable TieredStrategyProperties tiered) {
        TieredStrategyProperties strategy = tiered != null ? tiered : new TieredStrategyProperties();
        return strategy.getLayer1() != null && strategy.getLayer1().getTimeout() != null
                ? strategy.getLayer1().getTimeout().getLlmMs() : 0L;
    }

    /**
     * The time limit a first-layer model call of the decisions has, which tells a timeout apart (plan 3.5: the screen
     * states the conditions a cause is computed under); 0 or less when it is not known.
     */
    public long timeLimitMillis() {
        return timeLimitMillis.getAsLong();
    }

    // ----- measurements -----

    /**
     * Puts the wrong answers of a done measurement down to their causes; returns how many answers are wrong. A
     * measurement not done yet, or gone, is left alone.
     */
    public int classifyMeasurement(long measureId) {
        Optional<MeasureRow> found = measure(measureId);
        if (found.isEmpty() || !PromptQualityMeasurements.DONE.equals(found.get().status())) {
            return 0;
        }
        MeasureRow measure = found.get();
        Optional<PromptQualityCases.PublishedSet> set = cases.published(measure.caseSetId());
        if (set.isEmpty()) {
            log.warn("[PromptQualityCause] The case set of measurement {} is gone; its answers are not classified",
                    measureId);
            return 0;
        }
        Map<String, QualityCase> items = new HashMap<>();
        cases.read(set.get()).cases().cases().forEach(item -> items.put(item.key(), item));
        List<QualityCauseAnswer> answers = answers(measureId);
        Map<String, List<QualityCauseAnswer>> runs = new HashMap<>();
        answers.forEach(answer -> runs.computeIfAbsent(answer.caseKey(), key -> new ArrayList<>()).add(answer));
        long limit = timeLimitMillis.getAsLong();
        Set<String> wrong = new HashSet<>();
        int written = 0;
        for (QualityCauseAnswer answer : answers) {
            QualityCase item = items.get(answer.caseKey());
            if (item == null || QualityCauseClassifier.wrongOn(item, answer).isEmpty()) {
                continue;
            }
            QualityCauseResult result = QualityCauseClassifier.measured(item, answer, runs.get(answer.caseKey()),
                    limit);
            wrong.add(answer.caseKey() + "#" + answer.run());
            written += upsertAnswer(measure, answer, result, measuredBasis(item, answer, result));
        }
        // An answer that is no longer wrong, such as one of a case whose answer was changed, keeps no cause.
        for (Map<String, Object> row : jdbc.get().queryForList("select id, case_key, run_number from"
                + " ctxa_prompt_version_case_cause where measure_id = ?", measureId)) {
            if (!wrong.contains(row.get("case_key") + "#" + row.get("run_number"))) {
                jdbc.get().update("delete from ctxa_prompt_version_case_cause where id = ?", row.get("id"));
            }
        }
        if (written > 0) {
            log.info("[PromptQualityCause] Measurement {}: {} wrong answers put down to their causes, {} rows written",
                    measureId, wrong.size(), written);
        }
        return wrong.size();
    }

    /**
     * How many wrong answers of the measurement are put down to a cause, as they are kept: the count beside the view of
     * the causes, read without classifying again (a measurement is classified when it is done).
     */
    public int countOfMeasurement(long measureId) {
        Integer count = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_case_cause where"
                + " measure_id = ?", Integer.class, measureId);
        return count != null ? count : 0;
    }

    /** The causes of the wrong answers of the measurement, classified first; empty when there is no such measurement. */
    public Optional<Summary> ofMeasurement(long measureId) {
        if (measure(measureId).isEmpty()) {
            return Optional.empty();
        }
        classifyMeasurement(measureId);
        List<Cause> causes = jdbc.get().query(CAUSE_SQL + " where measure_id = ? order by case_key, run_number, id",
                this::cause, measureId);
        return Optional.of(summary(Source.MEASUREMENT, measureId, causes, 0));
    }

    private Optional<MeasureRow> measure(long measureId) {
        return jdbc.get().query("select id, registry_scope, prompt_key, case_set_id, status from"
                + " ctxa_prompt_version_measure where id = ?", (rs, row) -> new MeasureRow(rs.getLong(1),
                rs.getString(2), rs.getString(3), rs.getLong(4), rs.getString(5)), measureId).stream().findFirst();
    }

    private List<QualityCauseAnswer> answers(long measureId) {
        return jdbc.get().query("select case_key, run_number, first_action, model_action, final_action,"
                + " second_pass_outcome, decided_without_model, citation_state, cited_facts, present_facts,"
                + " flagged_facts, citation_findings, model_calls, decision_ms, measurement_failed"
                + " from ctxa_prompt_version_measure_answer where measure_id = ? order by case_key, run_number",
                (rs, row) -> new QualityCauseAnswer(rs.getString("case_key"), rs.getInt("run_number"),
                        QualityAction.parse(rs.getString("first_action")),
                        QualityAction.parse(rs.getString("model_action")),
                        QualityAction.parse(rs.getString("final_action")), rs.getBoolean("decided_without_model"),
                        "MODEL_ANSWER_UNUSABLE".equals(rs.getString("second_pass_outcome")),
                        measuredCitations(rs), firstPassCalls(rs.getString("model_calls")),
                        (Long) rs.getObject("decision_ms"), rs.getBoolean("measurement_failed")), measureId);
    }

    private QualityCauseCitations measuredCitations(ResultSet rs) throws SQLException {
        if (!"CHECKED".equals(rs.getString("citation_state"))) {
            return QualityCauseCitations.NOT_CHECKED;
        }
        List<QualityCauseCitations.Finding> findings = new ArrayList<>();
        JsonNode kept = read(rs.getString("citation_findings"));
        if (kept != null) {
            kept.forEach(finding -> findings.add(new QualityCauseCitations.Finding(text(finding.path("code")),
                    text(finding.path("fact")), text(finding.path("outcome")), finding.path("present").asBoolean())));
        }
        return new QualityCauseCitations(true, rs.getInt("cited_facts"), (Integer) rs.getObject("present_facts"),
                (Integer) rs.getObject("flagged_facts"), findings);
    }

    /** The times of the first pass's model calls, as the measurement kept them with their pass. */
    private List<Long> firstPassCalls(@Nullable String calls) {
        JsonNode kept = read(calls);
        List<Long> times = new ArrayList<>();
        if (kept != null) {
            kept.forEach(call -> {
                if (call.path("pass").asInt(1) == 1) {
                    times.add(call.path("callMs").isNumber() ? call.path("callMs").asLong() : null);
                }
            });
        }
        return times;
    }

    private Map<String, Object> measuredBasis(QualityCase item, QualityCauseAnswer answer, QualityCauseResult result) {
        Map<String, Object> actions = new LinkedHashMap<>();
        actions.put("first", name(answer.firstAction()));
        actions.put("model", name(answer.modelAction()));
        actions.put("final", name(answer.finalAction()));
        actions.put("allowed", item.expectation().allowedActions().stream().map(Enum::name).toList());
        Map<String, Object> basis = new LinkedHashMap<>();
        basis.put("source", Source.MEASUREMENT.name());
        basis.put("basis", result.basis().name());
        basis.put("actions", actions);
        basis.put("checks", checks(result));
        return basis;
    }

    private int upsertAnswer(MeasureRow measure, QualityCauseAnswer answer, QualityCauseResult result,
                             Map<String, Object> basis) {
        return jdbc.get().update("insert into ctxa_prompt_version_case_cause as c (registry_scope, prompt_key,"
                + " measure_id, case_key, run_number, category, rule_category, rule_basis, wrong_basis, classified_by,"
                + " classified_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (measure_id, case_key,"
                + " run_number) where measure_id is not null do update set " + RECLASSIFIED, measure.scope(),
                measure.prompt(), measure.id(), answer.caseKey(), answer.run(), result.cause().name(),
                result.cause().name(), write(basis), result.basis().name(), RULES, Timestamp.from(clock.instant()));
    }

    // ----- decisions -----

    /**
     * Puts the decisions an administrator rated inadequate in the period down to their causes; returns how many were
     * classified. A decision counts as rated inadequate while its latest evaluation is; the period is that of the
     * evaluation.
     *
     * @param scope the tenant whose decisions they are; the platform scope for every tenant
     */
    public int classifyDecisions(String scope, Instant from, Instant to) {
        return decide(scope, from, to).observations().size();
    }

    /** The causes of the decisions rated inadequate in the period, classified first. */
    public Summary ofDecisions(String scope, Instant from, Instant to) {
        Classified classified = decide(scope, from, to);
        Map<String, Cause> byObservation = new HashMap<>();
        List<String> observations = classified.observations();
        for (int start = 0; start < observations.size(); start += PAGE) {
            List<String> page = observations.subList(start, Math.min(observations.size(), start + PAGE));
            jdbc.get().query(CAUSE_SQL + " where observation_id in (" + String.join(", ",
                    Collections.nCopies(page.size(), "?")) + ")", this::cause, page.toArray())
                    .forEach(found -> byObservation.put(found.observationId(), found));
        }
        List<Cause> causes = observations.stream().map(byObservation::get).filter(Objects::nonNull).toList();
        return summary(Source.DECISION, null, causes, classified.withoutRecord());
    }

    private Classified decide(String scope, Instant from, Instant to) {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        String scopeName = scopeOf(scope);
        boolean platform = PromptVersionService.PLATFORM_SCOPE.equals(scopeName);
        String invalid = ZeroTrustDecisionOutcomes.Kind.EVALUATED_INVALID.name();
        List<Object> arguments = new ArrayList<>(List.of(ZeroTrustDecisionOutcomes.Kind.EVALUATED_VALID.name(),
                invalid, Timestamp.from(from), invalid, Timestamp.from(from), Timestamp.from(to)));
        if (!platform) {
            arguments.add(scopeName);
        }
        List<Evaluation> evaluations = jdbc.get().query("select observation_id, request_id, evaluation_reason from"
                + " (select distinct on (coalesce(o.observation_id, o.request_id)) o.observation_id, o.request_id,"
                + " o.outcome_kind, o.evaluation_reason, o.occurred_at, o.tenant_id, o.outcome_id from"
                + " ctxa_zt_decision_outcome o where o.outcome_kind in (?, ?) and o.occurred_at >= ? and"
                + " coalesce(o.observation_id, o.request_id) is not null order by coalesce(o.observation_id,"
                + " o.request_id), o.occurred_at desc, o.created_at desc, o.outcome_id desc) latest where"
                + " latest.outcome_kind = ? and latest.occurred_at >= ? and latest.occurred_at < ?"
                + (platform ? "" : " and latest.tenant_id = ?") + " order by latest.occurred_at, latest.outcome_id",
                (rs, row) -> new Evaluation(rs.getString(1), rs.getString(2), rs.getString(3)),
                arguments.toArray());
        Set<String> observations = new LinkedHashSet<>();
        int withoutRecord = 0;
        int written = 0;
        for (Evaluation evaluation : evaluations) {
            Optional<Map<String, Object>> decision = decisionRow(evaluation);
            if (decision.isEmpty()) {
                withoutRecord++;
                continue;
            }
            Map<String, Object> row = decision.get();
            String observationId = String.valueOf(row.get("observation_id"));
            if (observations.contains(observationId)) {
                continue;
            }
            String requestId = row.get("request_id") != null ? String.valueOf(row.get("request_id"))
                    : evaluation.requestId();
            QualityCauseDecision rated = rated(row, requestId, evaluation.reason());
            QualityCauseResult result = QualityCauseClassifier.rated(rated);
            String tenant = row.get("tenant_id") != null ? String.valueOf(row.get("tenant_id")) : null;
            written += upsertDecision(tenant != null && !tenant.isBlank() ? tenant.trim()
                    : PromptVersionService.PLATFORM_SCOPE, observationId, requestId, result, decisionBasis(rated,
                    result));
            observations.add(observationId);
        }
        if (written > 0) {
            log.info("[PromptQualityCause] {} decisions rated inadequate put down to their causes, {} rows written",
                    observations.size(), written);
        }
        return new Classified(List.copyOf(observations), withoutRecord);
    }

    /** The decision row the evaluation names, or the latest successful one of its request. */
    private Optional<Map<String, Object>> decisionRow(Evaluation evaluation) {
        String columns = "select observation_id, request_id, tenant_id, final_action, proposed_action,"
                + " decision_source, decision_change_cause, llm_decision_present, timeout_failure, technical_fallback,"
                + " parser_failure, model_unavailable, context_coverage_level, decision_summary_json,"
                + " citation_check_state, citation_cited_count, citation_present_count, citation_flagged_count"
                + " from ctxa_ai_security_decision_observation";
        List<Map<String, Object>> found = evaluation.observationId() != null
                ? jdbc.get().queryForList(columns + " where observation_id = ?", evaluation.observationId())
                : jdbc.get().queryForList(columns + " where request_id = ? and success = true order by created_at"
                + " desc limit 1", evaluation.requestId());
        return found.stream().findFirst();
    }

    private QualityCauseDecision rated(Map<String, Object> row, @Nullable String requestId,
                                       @Nullable String evaluationReason) {
        List<String> unknown = new ArrayList<>();
        JsonNode summary = read(textOf(row.get("decision_summary_json")));
        if (summary != null && summary.path("unknown").isObject()) {
            summary.path("unknown").fieldNames().forEachRemaining(unknown::add);
        }
        QualityCauseCitations citations = "CHECKED".equals(textOf(row.get("citation_check_state")))
                ? new QualityCauseCitations(true, intOf(row.get("citation_cited_count")),
                integerOf(row.get("citation_present_count")), integerOf(row.get("citation_flagged_count")), List.of())
                : QualityCauseCitations.NOT_CHECKED;
        return new QualityCauseDecision(textOf(row.get("decision_source")), textOf(row.get("decision_change_cause")),
                QualityAction.parse(textOf(row.get("proposed_action"))),
                QualityAction.parse(textOf(row.get("final_action"))),
                row.get("llm_decision_present") instanceof Boolean present ? present : null,
                Boolean.TRUE.equals(row.get("timeout_failure")), Boolean.TRUE.equals(row.get("technical_fallback")),
                Boolean.TRUE.equals(row.get("parser_failure")), Boolean.TRUE.equals(row.get("model_unavailable")),
                textOf(row.get("context_coverage_level")), unknown, citations, sourceTruth(requestId),
                evaluationReason);
    }

    /**
     * What the evidence audit found of the decision's facts compared with the host's own records: the latest
     * inspection of its seal that ran the source truth check.
     */
    private QualityCauseDecision.SourceTruth sourceTruth(@Nullable String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return QualityCauseDecision.SourceTruth.NOT_SEALED;
        }
        Integer sealed = jdbc.get().queryForObject("select count(*) from ctxa_sealed_evidence_package where"
                + " correlation_id = ?", Integer.class, requestId);
        if (sealed == null || sealed == 0) {
            return QualityCauseDecision.SourceTruth.NOT_SEALED;
        }
        List<String> inspections = jdbc.get().queryForList("select r.check_counts_json from"
                + " ctxa_prompt_inspection_result r join ctxa_sealed_evidence_package p on p.package_id = r.package_id"
                + " where p.correlation_id = ? order by r.inspected_at desc, r.id desc", String.class, requestId);
        for (String counts : inspections) {
            JsonNode checks = read(counts);
            if (checks == null) {
                continue;
            }
            for (JsonNode check : checks) {
                if (SourceTruthCheck.CODE.equals(text(check.path("checkCode")))) {
                    return QualityCauseDecision.SourceTruth.inspected(check.path("matched").asInt(),
                            check.path("mismatched").asInt(), check.path("unverifiable").asInt());
                }
            }
        }
        return QualityCauseDecision.SourceTruth.NOT_INSPECTED;
    }

    private Map<String, Object> decisionBasis(QualityCauseDecision decision, QualityCauseResult result) {
        Map<String, Object> actions = new LinkedHashMap<>();
        actions.put("model", name(decision.proposedAction()));
        actions.put("final", name(decision.finalAction()));
        Map<String, Object> basis = new LinkedHashMap<>();
        basis.put("source", Source.DECISION.name());
        basis.put("evaluationReason", decision.evaluationReason());
        basis.put("actions", actions);
        basis.put("checks", checks(result));
        return basis;
    }

    private int upsertDecision(String scope, String observationId, @Nullable String requestId,
                               QualityCauseResult result, Map<String, Object> basis) {
        return jdbc.get().update("insert into ctxa_prompt_version_case_cause as c (registry_scope, prompt_key,"
                + " request_id, observation_id, category, rule_category, rule_basis, classified_by, classified_at)"
                + " values (?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (observation_id) where observation_id is not null"
                + " do update set " + RECLASSIFIED, scope, SecurityDecisionPromptDocument.PROMPT, requestId,
                observationId, result.cause().name(), result.cause().name(), write(basis), RULES,
                Timestamp.from(clock.instant()));
    }

    // ----- reading and correcting -----

    /** The cause in the scope; the platform scope finds a cause of any scope. */
    public Optional<Cause> find(String scope, long id) {
        String scopeName = scopeOf(scope);
        boolean platform = PromptVersionService.PLATFORM_SCOPE.equals(scopeName);
        return (platform ? jdbc.get().query(CAUSE_SQL + " where id = ?", this::cause, id)
                : jdbc.get().query(CAUSE_SQL + " where id = ? and registry_scope = ?", this::cause, id, scopeName))
                .stream().findFirst();
    }

    /**
     * An administrator puts the answer down to another cause. The row keeps who did it, when, and the category it
     * replaced; classifying again never overwrites it. Putting it down to the cause it has pins it, likewise.
     *
     * @throws RefusedException when there is no such cause in the scope, the category is none of the seven, or a
     *                          measured answer is put down to an input error
     */
    public Cause correct(String scope, long id, QualityCause category, String actor) {
        if (category == null || category == QualityCause.UNCLASSIFIED) {
            throw new RefusedException(Refusal.CATEGORY, "An answer is put down to one of the seven causes");
        }
        Cause found = find(scope, id).orElseThrow(() -> new RefusedException(Refusal.NOT_FOUND,
                "There is no cause " + id));
        if (category.decisionsOnly() && found.source() == Source.MEASUREMENT) {
            throw new RefusedException(Refusal.DECISIONS_ONLY, "Only a decision is put down to an input error");
        }
        String who = actor != null && !actor.isBlank() ? actor.trim() : "system";
        jdbc.get().update("update ctxa_prompt_version_case_cause set previous_category = category, category = ?,"
                + " corrected_by = ?, corrected_at = ? where id = ?", category.name(), truncate(who, 128),
                Timestamp.from(clock.instant()), id);
        log.info("[PromptQualityCause] Cause {} put down to {} by {}, the rules said {}", id, category, who,
                found.ruleCategory());
        return find(scope, id).orElseThrow();
    }

    private Summary summary(Source source, @Nullable Long measureId, List<Cause> causes, int withoutRecord) {
        Map<QualityCause, int[]> tally = new EnumMap<>(QualityCause.class);
        for (QualityCause cause : QualityCause.values()) {
            tally.put(cause, new int[2]);
        }
        for (Cause cause : causes) {
            tally.get(cause.category())[0]++;
            for (QualityCauseCheck check : cause.checks()) {
                if (check.state() == QualityCauseCheck.State.NOT_COMPUTED) {
                    tally.get(check.cause())[1]++;
                }
            }
        }
        List<Count> counts = new ArrayList<>();
        tally.forEach((cause, numbers) -> counts.add(new Count(cause, cause.fix(), numbers[0], numbers[1])));
        List<Cause> forNewVersion = causes.stream()
                .filter(cause -> cause.fix() != null && cause.fix().opensVersionEditor()).toList();
        return new Summary(source, measureId, List.copyOf(counts), List.copyOf(causes), forNewVersion, withoutRecord);
    }

    // ----- rows -----

    /**
     * What classifying again writes: the rule's category, basis and time, and the category unless an administrator
     * corrected it; nothing when the rule comes to what the row has.
     */
    private static final String RECLASSIFIED = "rule_category = excluded.rule_category,"
            + " rule_basis = excluded.rule_basis, wrong_basis = excluded.wrong_basis,"
            + " category = case when c.corrected_by is null then excluded.category else c.category end,"
            + " classified_by = excluded.classified_by, classified_at = excluded.classified_at"
            + " where c.rule_category is distinct from excluded.rule_category"
            + " or c.rule_basis is distinct from excluded.rule_basis"
            + " or c.wrong_basis is distinct from excluded.wrong_basis";

    private static final String CAUSE_SQL = "select id, registry_scope, prompt_key, measure_id, case_key, run_number,"
            + " request_id, observation_id, category, rule_category, rule_basis, wrong_basis, classified_by,"
            + " classified_at, corrected_by, corrected_at, previous_category from ctxa_prompt_version_case_cause";

    private Cause cause(ResultSet rs, int row) throws SQLException {
        JsonNode basis = read(rs.getString("rule_basis"));
        List<QualityCauseCheck> checks = new ArrayList<>();
        Map<String, Object> actions = new LinkedHashMap<>();
        if (basis != null) {
            basis.path("checks").forEach(check -> {
                QualityCause cause = QualityCause.parse(text(check.path("cause")));
                if (cause != null) {
                    List<String> details = new ArrayList<>();
                    check.path("details").forEach(detail -> details.add(detail.asText()));
                    checks.add(new QualityCauseCheck(cause, QualityCauseCheck.State.valueOf(text(check.path("state"))),
                            text(check.path("reason")), details));
                }
            });
            basis.path("actions").fields().forEachRemaining(entry -> actions.put(entry.getKey(),
                    entry.getValue().isArray() ? texts(entry.getValue())
                            : entry.getValue().isNull() ? null : entry.getValue().asText()));
        }
        Long measureId = (Long) rs.getObject("measure_id");
        QualityCause category = QualityCause.parse(rs.getString("category"));
        return new Cause(rs.getLong("id"), rs.getString("registry_scope"), rs.getString("prompt_key"),
                measureId != null ? Source.MEASUREMENT : Source.DECISION, measureId, rs.getString("case_key"),
                (Integer) rs.getObject("run_number"), rs.getString("request_id"), rs.getString("observation_id"),
                category != null ? category : QualityCause.UNCLASSIFIED, QualityCause.parse(rs.getString(
                "rule_category")), basisOf(rs.getString("wrong_basis")), List.copyOf(checks),
                Collections.unmodifiableMap(actions), rs.getString("classified_by"),
                rs.getTimestamp("classified_at").toInstant(), rs.getString("corrected_by"),
                instant(rs.getTimestamp("corrected_at")), QualityCause.parse(rs.getString("previous_category")));
    }

    private static List<Map<String, Object>> checks(QualityCauseResult result) {
        List<Map<String, Object>> checks = new ArrayList<>();
        for (QualityCauseCheck check : result.checks()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("cause", check.cause().name());
            entry.put("state", check.state().name());
            entry.put("reason", check.reason());
            entry.put("details", check.details());
            checks.add(entry);
        }
        return checks;
    }

    @Nullable
    private static QualityCauseBasis basisOf(@Nullable String name) {
        if (name == null) {
            return null;
        }
        for (QualityCauseBasis basis : QualityCauseBasis.values()) {
            if (basis.name().equals(name)) {
                return basis;
            }
        }
        return null;
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("A cause could not be written: " + exception.getOriginalMessage(),
                    exception);
        }
    }

    @Nullable
    private JsonNode read(@Nullable String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return json.readTree(text);
        }
        catch (JsonProcessingException exception) {
            log.warn("[PromptQualityCause] A kept value could not be read and is left out: {}",
                    exception.getOriginalMessage());
            return null;
        }
    }

    private static List<String> texts(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(value -> values.add(value.asText()));
        return List.copyOf(values);
    }

    @Nullable
    private static String text(JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }

    @Nullable
    private static String textOf(@Nullable Object value) {
        return value != null ? String.valueOf(value) : null;
    }

    private static int intOf(@Nullable Object value) {
        return value instanceof Number number ? number.intValue() : 0;
    }

    @Nullable
    private static Integer integerOf(@Nullable Object value) {
        return value instanceof Number number ? number.intValue() : null;
    }

    private static String name(@Nullable QualityAction action) {
        return action != null ? action.name() : null;
    }

    @Nullable
    private static Instant instant(@Nullable Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }

    @Nullable
    private static String truncate(@Nullable String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }

    private static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }
}
