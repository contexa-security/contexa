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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionDetail;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionPage;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.EvaluationSaved;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.OutcomeView;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ReasonView;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ReviewItem;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ReviewPage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.jdbc.core.JdbcOperations;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The decision records of the console (console design 6.4): the list, read by time with a cursor and filtered by the
 * address; one decision with its reasons, its explanations, its comparison with the usual, the facts the model did not
 * know and what came of it; the review queue and an administrator's evaluation (console decision 11.3).
 */
@Slf4j
public class ZeroTrustDecisionRecords {

    /** The filters the list takes; each names a column of the decision row. */
    /**
     * The filters the list takes; each names a column of the decision row. The address alone sets the ones the
     * screens link with (design 6.1, 6.2): the baseline, the weekday and the four-hour band of the decision's hour,
     * and the users challenged at least so often in the period.
     */
    public record Filter(String action, String source, String hypothesis, String actor, String resourceClass,
                         String outcome, String mode, String query, String baseline, Integer weekday, Integer band,
                         Integer challengedAtLeast) {

        public Filter(String action, String source, String hypothesis, String actor, String resourceClass,
                      String outcome, String mode, String query) {
            this(action, source, hypothesis, actor, resourceClass, outcome, mode, query, null, null, null, null);
        }
    }

    /** The baseline filter of the decisions made without an established baseline (provisional, none or unknown). */
    public static final String BASELINE_NOT_ESTABLISHED = "NOT_ESTABLISHED";
    /** The action filter of the stopped decisions: a challenge, an escalation or a block. */
    static final String STOPPED = "STOPPED";
    /** The review entries a page of the queue shows. */
    static final int REVIEW_PAGE = 20;

    /** The decisions a page of the list shows: the admin console's lists keep one screen of rows, not fifty. */
    static final int PAGE = 20;
    /** The slowest decisions the list shows in its slowest-first order. */
    static final int SLOWEST = 20;
    /** The most rows one CSV carries. */
    static final int CSV_LIMIT = 10_000;
    private static final Set<String> ACTIONS = Set.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK",
            ZeroTrustConsoleService.NO_DECISION, STOPPED);
    private static final Set<String> BASELINES = Set.of("ESTABLISHED", "PROVISIONAL", "NONE", BASELINE_NOT_ESTABLISHED);
    private static final Set<String> REVIEW_REASONS = Set.of("SAMPLE", "RULE_BREACH", "SHADOW_BLOCK");
    private static final Set<String> SOURCES = Set.of("MODEL", "ENGINE_CHANGED", "MODEL_LESS");
    private static final Set<String> ACTORS = Set.of("HUMAN", "AGENT", "SERVICE");
    private static final Set<String> MODES = Set.of("SHADOW", "ENFORCE");
    private static final Set<String> OUTCOMES = Set.of("NONE", "CHALLENGE_PASSED", "CHALLENGE_FAILED",
            "CHALLENGE_EXPIRED", "UNBLOCK_REQUESTED", "ADMIN_RELEASED", "BLOCK_KEPT", "EVALUATED_VALID",
            "EVALUATED_INVALID");

    /** The most audit records of one request the detail reads to find its decision's (a request judged again has two). */
    private static final int AUDIT_RECORDS_OF_A_REQUEST = 20;
    /**
     * The sentence the second analysis adds when it ends an ESCALATE ({@code Layer2ExpertStrategy}): the engine's words
     * in a row stored before K25 kept them apart.
     */
    private static final Pattern TERMINALIZED = Pattern.compile(
            "[^\\n]*, so final autonomous action was terminalized to [A-Z_]+ by tiered strategy policy\\.$");

    private static final String ROW_COLUMNS = """
            o.observation_id, o.created_at, o.user_id, COALESCE(NULLIF(o.resource_id, ''), o.request_path),
            o.http_method, o.resource_class, o.final_action, o.decision_source, o.most_likely_hypothesis,
            r.reason_code, o.total_analysis_ms, o.decision_boundary_mode, o.actor_kind, o.attempt_kind,
            (SELECT d.outcome_kind FROM ctxa_zt_decision_outcome d
              WHERE d.observation_id = o.observation_id ORDER BY d.occurred_at DESC LIMIT 1)""";

    private final Supplier<JdbcOperations> jdbc;
    private final ZeroTrustDecisionOutcomes outcomes;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    /** Whether the decisions in force and the baselines are kept in this node's memory (console design 6.0). */
    private volatile boolean standalone;

    public ZeroTrustDecisionRecords(Supplier<JdbcOperations> jdbc, ZeroTrustDecisionOutcomes outcomes,
                                    MessageSource messages, ObjectMapper objectMapper, Clock clock) {
        this.jdbc = jdbc == null ? () -> null : jdbc;
        this.outcomes = outcomes;
        this.messages = messages;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.clock = clock != null ? clock : Clock.systemDefaultZone();
    }

    public void setStandalone(boolean standalone) {
        this.standalone = standalone;
    }

    // ----- the list -----

    public DecisionPage list(ZeroTrustConsoleRange range, String tenant, Filter filter, String cursor) {
        List<DecisionRow> rows = rows(range, tenant, filter, cursor, PAGE + 1);
        String next = null;
        if (rows.size() > PAGE) {
            rows = rows.subList(0, PAGE);
            DecisionRow last = rows.get(PAGE - 1);
            next = encodeCursor(Instant.parse(last.createdAt()), last.observationId());
        }
        return new DecisionPage(List.copyOf(rows), next);
    }

    /** The rows of the list for a CSV, as many as {@link #CSV_LIMIT}. */
    public List<DecisionRow> export(ZeroTrustConsoleRange range, String tenant, Filter filter) {
        return rows(range, tenant, filter, null, CSV_LIMIT);
    }

    /**
     * Console plan 5-2 ③: the slowest decisions of the period under the filter, the longest analysis first, as many as
     * {@link #SLOWEST} (the AI monitor showed its ten slowest requests). One page: the order has no cursor.
     */
    public DecisionPage slowest(ZeroTrustConsoleRange range, String tenant, Filter filter) {
        return new DecisionPage(List.copyOf(rows(range, tenant, filter, null, SLOWEST, true)), null);
    }

    private List<DecisionRow> rows(ZeroTrustConsoleRange range, String tenant, Filter filter, String cursor, int limit) {
        return rows(range, tenant, filter, cursor, limit, false);
    }

    private List<DecisionRow> rows(ZeroTrustConsoleRange range, String tenant, Filter filter, String cursor, int limit,
                                   boolean slowestFirst) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        Filter given = filter != null ? filter : new Filter(null, null, null, null, null, null, null, null);
        List<Object> args = new ArrayList<>(List.of(range.fromTimestamp(), range.toTimestamp()));
        StringBuilder where = new StringBuilder(" WHERE o.created_at >= ? AND o.created_at < ? AND o.test_run_id IS NULL");
        String action = allowed(given.action(), ACTIONS);
        if (ZeroTrustConsoleService.NO_DECISION.equals(action)) {
            where.append(" AND o.attempt_kind IN ('TIMEOUT', 'REJECTED')");
        } else {
            where.append(" AND o.attempt_kind = 'FIRST' AND o.final_action IN ('ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK')");
            if (STOPPED.equals(action)) {
                where.append(" AND o.final_action IN ('CHALLENGE', 'ESCALATE', 'BLOCK')");
            } else if (action != null) {
                where.append(" AND o.final_action = ?");
                args.add(action);
            }
        }
        equal(where, args, "o.decision_source", allowed(given.source(), SOURCES));
        equal(where, args, "o.actor_kind", allowed(given.actor(), ACTORS));
        equal(where, args, "o.decision_boundary_mode", allowed(given.mode(), MODES));
        equal(where, args, "o.most_likely_hypothesis", code(given.hypothesis(), 16));
        equal(where, args, "o.resource_class", code(given.resourceClass(), 32));
        equal(where, args, "o.tenant_id", tenant);
        String baseline = allowed(given.baseline(), BASELINES);
        if (BASELINE_NOT_ESTABLISHED.equals(baseline)) {
            where.append(" AND (o.baseline_status IS NULL OR o.baseline_status <> 'ESTABLISHED')");
        } else {
            equal(where, args, "o.baseline_status", baseline);
        }
        // Design 6.2: a cell of the weekday and four-hour band map, read on the decision's hour as the map is.
        if (given.weekday() != null && given.weekday() >= 1 && given.weekday() <= 7) {
            where.append(" AND CAST(EXTRACT(ISODOW FROM o.created_at) AS INTEGER) = ?");
            args.add(given.weekday());
        }
        if (given.band() != null && given.band() >= 0 && given.band() <= 5) {
            where.append(" AND CAST(FLOOR(EXTRACT(HOUR FROM o.created_at) / 4) AS INTEGER) = ?");
            args.add(given.band());
        }
        if (given.challengedAtLeast() != null && given.challengedAtLeast() > 0) {
            // Design 6.2: the users of the burden bar, challenged at least so often in the period
            where.append(" AND o.user_id IN (SELECT c.user_id FROM ctxa_ai_security_decision_observation c"
                    + " WHERE c.created_at >= ? AND c.created_at < ? AND c.attempt_kind = 'FIRST'"
                    + " AND c.final_action = 'CHALLENGE' AND c.test_run_id IS NULL"
                    + (tenant != null ? " AND c.tenant_id = ?" : "")
                    + " GROUP BY c.user_id HAVING COUNT(*) >= ?)");
            args.add(range.fromTimestamp());
            args.add(range.toTimestamp());
            if (tenant != null) {
                args.add(tenant);
            }
            args.add(given.challengedAtLeast());
        }
        String outcome = allowed(given.outcome(), OUTCOMES);
        if ("NONE".equals(outcome)) {
            where.append(" AND NOT EXISTS (SELECT 1 FROM ctxa_zt_decision_outcome d WHERE d.observation_id = o.observation_id)");
        } else if (outcome != null) {
            where.append(" AND EXISTS (SELECT 1 FROM ctxa_zt_decision_outcome d WHERE d.observation_id = o.observation_id"
                    + " AND d.outcome_kind = ?)");
            args.add(outcome);
        }
        String query = given.query() == null ? null : given.query().trim();
        if (query != null && !query.isEmpty()) {
            String bounded = query.length() > 200 ? query.substring(0, 200) : query;
            // a resource of the ranked resources is its id when the decision named one, else its path
            where.append(" AND (o.user_id = ? OR o.request_id = ? OR o.observation_id = ? OR o.resource_id = ?"
                    + " OR o.request_path LIKE ?)");
            args.add(bounded);
            args.add(bounded);
            args.add(bounded);
            args.add(bounded);
            args.add(likePrefix(bounded));
        }
        Object[] position = slowestFirst ? null : decodeCursor(cursor);
        if (position != null) {
            where.append(" AND (o.created_at < ? OR (o.created_at = ? AND o.observation_id < ?))");
            args.add(position[0]);
            args.add(position[0]);
            args.add(position[1]);
        }
        String order = " ORDER BY o.created_at DESC, o.observation_id DESC";
        if (slowestFirst) {
            where.append(" AND o.total_analysis_ms IS NOT NULL");
            order = " ORDER BY o.total_analysis_ms DESC, o.observation_id DESC";
        }
        args.add(limit);
        return operations.query("SELECT " + ROW_COLUMNS
                + " FROM ctxa_ai_security_decision_observation o"
                + " LEFT JOIN ctxa_zt_decision_reason r ON r.observation_id = o.observation_id AND r.reason_rank = 1"
                + where + order + " LIMIT ?", this::row, args.toArray());
    }

    private DecisionRow row(ResultSet rs, int index) throws SQLException {
        String reason = rs.getString(10);
        boolean noDecision = !"FIRST".equals(rs.getString(14));
        long total = rs.getLong(11);
        Long totalMs = rs.wasNull() ? null : total;
        return new DecisionRow(rs.getString(1), instant(rs, 2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getString(6), noDecision ? ZeroTrustConsoleService.NO_DECISION : rs.getString(7), rs.getString(8),
                rs.getString(9), reason, reason == null ? null : ZeroTrustConsoleService.groupOf(reason),
                rs.getString(15), totalMs, rs.getString(12), rs.getString(13));
    }

    // ----- one decision -----

    /**
     * The decision row of a request, for the screens that know a request and not its row (the security event log, the
     * blocked users): its latest first decision, else its latest row. Null when the request has no decision row.
     */
    public String observationOfRequest(String requestId) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || requestId == null || requestId.isBlank()) {
            return null;
        }
        List<String> found = operations.queryForList("""
                SELECT observation_id
                  FROM ctxa_ai_security_decision_observation
                 WHERE request_id = ?
                 ORDER BY CASE WHEN attempt_kind = 'FIRST' THEN 0 ELSE 1 END, created_at DESC
                 LIMIT 1
                """, String.class, requestId);
        return found.isEmpty() ? null : found.get(0);
    }

    public DecisionDetail detail(String observationId, Locale locale) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || observationId == null) {
            return null;
        }
        List<Map<String, Object>> found = operations.queryForList("""
                SELECT observation_id, request_id, event_id, idempotency_key, created_at, decision_boundary_mode,
                       actor_kind, final_action,
                       proposed_action, decision_source, decision_change_cause, enforcement_timing, total_analysis_ms,
                       prompt_bundle_version, model_id, decision_summary_json, baseline_status, context_coverage_level,
                       queue_wait_ms, prompt_build_ms, rag_vector_ms, llm_latency_ms, parse_ms, persist_ms, user_wait_ms,
                       user_id, COALESCE(NULLIF(resource_id, ''), request_path) AS resource, resource_class, attempt_kind,
                       decision_stage, model_call_count, prompt_tokens, output_tokens
                  FROM ctxa_ai_security_decision_observation
                 WHERE observation_id = ?
                """, observationId);
        if (found.isEmpty()) {
            return null;
        }
        Map<String, Object> row = found.get(0);
        String requestId = text(row.get("request_id"));
        Map<String, Object> summary = summary(text(row.get("decision_summary_json")));
        List<ReasonView> reasons = new ArrayList<>();
        Map<String, Map<String, Object>> cited = new LinkedHashMap<>();
        if (summary.get("reasons") instanceof List<?> list) {
            for (Object entry : list) {
                if (entry instanceof Map<?, ?> map && map.get("code") != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> reason = (Map<String, Object>) map;
                    cited.putIfAbsent(String.valueOf(reason.get("code")), reason);
                }
            }
        }
        operations.query("""
                SELECT reason_rank, reason_code, reason_group, fact_id, fact_name
                  FROM ctxa_zt_decision_reason
                 WHERE observation_id = ?
                 ORDER BY reason_rank
                """, rs -> {
            Map<String, Object> reason = cited.getOrDefault(rs.getString(2), Map.of());
            reasons.add(new ReasonView(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4),
                    rs.getString(5), reason.get("factValue") != null ? String.valueOf(reason.get("factValue")) : null));
        }, observationId);
        List<OutcomeView> outcomeViews = operations.query("""
                SELECT outcome_kind, occurred_at, actor, note, evaluation_reason
                  FROM ctxa_zt_decision_outcome
                 WHERE observation_id = ?
                 ORDER BY occurred_at
                """, (rs, n) -> new OutcomeView(rs.getString(1), instant(rs, 2), rs.getString(3), rs.getString(4),
                rs.getString(5)), observationId);
        // K24: a request judged again has a decision, an audit record and a sealed package per judgement; each
        // decision opens its own, by its event.
        Long auditId = auditOf(operations, requestId, text(row.get("event_id")));
        String packageId = packageOf(operations, observationId, text(row.get("idempotency_key")));
        String reviewReason = first(operations.queryForList(
                "SELECT review_reason FROM ctxa_zt_review_queue WHERE observation_id = ? AND review_status = 'PENDING'",
                String.class, observationId));
        Map<String, Long> timings = new LinkedHashMap<>();
        timings.put("QUEUE", number(row.get("queue_wait_ms")));
        timings.put("PREPARE", number(row.get("prompt_build_ms")));
        timings.put("RAG", number(row.get("rag_vector_ms")));
        timings.put("MODEL", number(row.get("llm_latency_ms")));
        timings.put("PARSE", number(row.get("parse_ms")));
        timings.put("PERSIST", number(row.get("persist_ms")));
        timings.put("USER_WAIT", number(row.get("user_wait_ms")));
        String action = "FIRST".equals(text(row.get("attempt_kind"))) ? text(row.get("final_action"))
                : ZeroTrustConsoleService.NO_DECISION;
        String lastOutcome = outcomeViews.isEmpty() ? null : outcomeViews.get(outcomeViews.size() - 1).kind();
        String mainReason = reasons.isEmpty() ? null : reasons.get(0).code();
        String source = text(row.get("decision_source"));
        String[] sentences = sentences(summary, source);
        String stage = text(row.get("decision_stage"));
        Integer modelCalls = integer(row.get("model_call_count"));
        String bundle = text(row.get("prompt_bundle_version"));
        return new DecisionDetail(observationId, requestId, instantText(row.get("created_at")),
                text(row.get("decision_boundary_mode")), text(row.get("actor_kind")), action,
                text(row.get("proposed_action")), source,
                text(row.get("decision_change_cause")), text(row.get("enforcement_timing")),
                number(row.get("total_analysis_ms")), text(row.get("prompt_bundle_version")), text(row.get("model_id")),
                !reasons.isEmpty() || summary.containsKey("hypotheses"),
                conclusion(action, mainReason, lastOutcome, locale), reasons, sentences[0],
                listOfMaps(summary.get("hypotheses")),
                new ZeroTrustDeviationWords(messages, locale).words(listOfMaps(summary.get("deviations"))),
                summary.get("unknown") instanceof Map<?, ?> unknown ? copy(unknown) : Map.of(),
                text(row.get("baseline_status")), text(row.get("context_coverage_level")), outcomeViews, timings,
                auditId, packageId, reviewReason != null, text(row.get("user_id")),
                text(row.get("resource")), text(row.get("resource_class")), sentences[1],
                Boolean.TRUE.equals(summary.get("usualKept")), listOfMaps(summary.get("ruleBreaches")), reviewReason,
                standalone, stage, modelCalls, number(row.get("prompt_tokens")), number(row.get("output_tokens")),
                modelCalls == null ? null : modelCalls > ("LAYER2".equals(stage) ? 2 : 1),
                number(summary.get("baselineLearned")), integer(summary.get("baselineDays")),
                // Design 6.4 (5): a passed step-up and a release learn the request into the baseline
                outcomeViews.stream().anyMatch(outcome -> "CHALLENGE_PASSED".equals(outcome.kind())
                        || "ADMIN_RELEASED".equals(outcome.kind())),
                bundle == null ? null : PromptVersionNames.number(bundle).stream().boxed().findFirst().orElse(null));
    }

    /**
     * K24: the audit record of the decision's own event. The audit records of a request share its correlation; the
     * event each was written for is in its details.
     */
    private Long auditOf(JdbcOperations operations, String requestId, String eventId) {
        if (requestId == null || eventId == null) {
            return null;
        }
        List<Map<String, Object>> records = operations.queryForList("""
                SELECT id, details FROM ctxa_audit_log
                 WHERE correlation_id = ? AND event_category = 'SECURITY_DECISION'
                 ORDER BY timestamp DESC LIMIT ?
                """, truncate(requestId, 64), AUDIT_RECORDS_OF_A_REQUEST);
        for (Map<String, Object> record : records) {
            if (eventId.equals(field(text(record.get("details")), "eventId"))) {
                return number(record.get("id"));
            }
        }
        return null;
    }

    /**
     * K24: the sealed package of the decision's own processing, by the processing identity the package and the decision
     * row both keep (the row's column for a final decision, else its metadata).
     */
    private String packageOf(JdbcOperations operations, String observationId, String identity) {
        String key = identity;
        if (key == null) {
            key = field(first(operations.queryForList(
                    "SELECT metadata_json FROM ctxa_ai_security_decision_observation WHERE observation_id = ?",
                    String.class, observationId)), SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
        }
        if (key == null) {
            return null;
        }
        return first(operations.queryForList("""
                SELECT package_id FROM ctxa_sealed_evidence_package
                 WHERE idempotency_key = ?
                 ORDER BY captured_at DESC LIMIT 1
                """, String.class, key));
    }

    /**
     * K25: the model's own sentence and the engine's. A row stored before K25 kept one sentence for both: a decision
     * made without the model holds the engine's, and the sentence the second analysis adds when it ends an ESCALATE is
     * the engine's.
     */
    static String[] sentences(Map<String, Object> summary, String source) {
        if (summary.containsKey("modelReason") || summary.containsKey("engineReason")) {
            return new String[] {text(summary.get("modelReason")), text(summary.get("engineReason"))};
        }
        String reason = text(summary.get("reason"));
        if (reason == null || reason.isBlank()) {
            return new String[] {null, null};
        }
        if ("MODEL_LESS".equals(source)) {
            return new String[] {null, reason};
        }
        Matcher terminalized = TERMINALIZED.matcher(reason);
        if (terminalized.find()) {
            String model = reason.substring(0, terminalized.start()).trim();
            return new String[] {model.isEmpty() ? null : model, terminalized.group().trim()};
        }
        return new String[] {reason, null};
    }

    /** A text field of a JSON object, or null when the text is no JSON object or has no such field. */
    private String field(String json, String name) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(json);
            return node != null && node.hasNonNull(name) ? node.get(name).asText() : null;
        } catch (Exception unreadable) {
            return null;
        }
    }

    /**
     * Console design 6.4: the conclusion in a fixed form made of the action, the group of the main reason and what
     * came of it; the model's own sentence is shown apart as its words.
     */
    String conclusion(String action, String mainReason, String outcome, Locale locale) {
        Locale resolved = locale == null ? Locale.ENGLISH : locale;
        String actionText = message("zt.console.action." + action, action, resolved);
        String reasonText = null;
        if (mainReason != null) {
            // The reason code's own words; its group's words when no message names the code.
            String group = ZeroTrustConsoleService.groupOf(mainReason);
            reasonText = message("zt.console.reasonCode." + mainReason,
                    message("zt.console.reasonGroup." + group, group, resolved), resolved);
        }
        String outcomeText = outcome == null ? null : message("zt.console.outcome." + outcome, outcome, resolved);
        if (reasonText == null && outcomeText == null) {
            return message("zt.console.conclusion.action", actionText, resolved, actionText);
        }
        if (outcomeText == null) {
            return message("zt.console.conclusion.reason", actionText + ": " + reasonText, resolved, actionText,
                    reasonText);
        }
        if (reasonText == null) {
            return message("zt.console.conclusion.outcome", actionText + " - " + outcomeText, resolved, actionText,
                    outcomeText);
        }
        return message("zt.console.conclusion.full", actionText + ": " + reasonText + " - " + outcomeText, resolved,
                actionText, reasonText, outcomeText);
    }

    // ----- review -----

    /** The first page of the review queue. */
    public List<ReviewItem> reviewQueue() {
        return reviewPage(null, null).items();
    }

    /**
     * A page of the review queue (design 6.4: pages of the list's rows), the latest sample day first, read on from a
     * cursor; only the entries waiting for one reason when it is given (the daily sample, a broken rule, a block SHADOW
     * would have made).
     */
    public ReviewPage reviewPage(String cursor, String reason) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return new ReviewPage(List.of(), null, 0);
        }
        String why = allowed(reason, REVIEW_REASONS);
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE q.review_status = 'PENDING'");
        if (why != null) {
            where.append(" AND q.review_reason = ?");
            args.add(why);
        }
        Long pending = operations.queryForObject("SELECT COUNT(*) FROM ctxa_zt_review_queue q" + where, Long.class,
                args.toArray());
        Object[] position = decodeReviewCursor(cursor);
        if (position != null) {
            where.append(" AND (q.sample_day < ? OR (q.sample_day = ? AND (o.created_at < ?"
                    + " OR (o.created_at = ? AND q.observation_id < ?))))");
            args.add(position[0]);
            args.add(position[0]);
            args.add(position[1]);
            args.add(position[1]);
            args.add(position[2]);
        }
        args.add(REVIEW_PAGE + 1);
        List<ReviewItem> items = operations.query("""
                SELECT q.observation_id, q.sample_day, o.created_at, o.user_id,
                       COALESCE(NULLIF(o.resource_id, ''), o.request_path), o.final_action, o.most_likely_hypothesis,
                       r.reason_code, q.review_reason
                  FROM ctxa_zt_review_queue q
                  JOIN ctxa_ai_security_decision_observation o ON o.observation_id = q.observation_id
                  LEFT JOIN ctxa_zt_decision_reason r ON r.observation_id = o.observation_id AND r.reason_rank = 1
                """ + where + """

                 ORDER BY q.sample_day DESC, o.created_at DESC, q.observation_id DESC
                 LIMIT ?
                """, (rs, n) -> new ReviewItem(rs.getString(1), String.valueOf(rs.getDate(2)), instant(rs, 3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9)),
                args.toArray());
        String next = null;
        if (items.size() > REVIEW_PAGE) {
            items = items.subList(0, REVIEW_PAGE);
            ReviewItem last = items.get(REVIEW_PAGE - 1);
            next = encodeCursor(Instant.parse(last.createdAt()), last.sampleDay() + "|" + last.observationId());
        }
        return new ReviewPage(List.copyOf(items), next, pending == null ? 0 : pending);
    }

    /** The sample day, the creation time and the id a review cursor names, or null to start from the top. */
    static Object[] decodeReviewCursor(String cursor) {
        Object[] position = decodeCursor(cursor);
        if (position == null) {
            return null;
        }
        String rest = String.valueOf(position[1]);
        int bar = rest.indexOf('|');
        if (bar <= 0) {
            return null;
        }
        try {
            return new Object[] {Date.valueOf(rest.substring(0, bar)), position[0], rest.substring(bar + 1)};
        } catch (IllegalArgumentException unreadable) {
            return null;
        }
    }

    /**
     * Keeps an administrator's evaluation of a decision as its outcome and closes its review entry. An invalid one
     * names its reason; a decision that does not exist is refused.
     *
     * @throws IllegalArgumentException when the evaluation says neither valid nor invalid, or names no known reason
     */
    public EvaluationSaved evaluate(String observationId, Evaluation evaluation, String reviewer) {
        if (evaluation == null || evaluation.valid() == null) {
            throw new IllegalArgumentException("An evaluation says whether the decision was valid");
        }
        ZeroTrustDecisionOutcomes.EvaluationReason reason = null;
        if (!evaluation.valid()) {
            try {
                reason = evaluation.reason() == null ? ZeroTrustDecisionOutcomes.EvaluationReason.OTHER
                        : ZeroTrustDecisionOutcomes.EvaluationReason.valueOf(evaluation.reason().trim()
                        .toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException unknown) {
                throw new IllegalArgumentException("Unknown evaluation reason: " + evaluation.reason());
            }
        }
        JdbcOperations operations = jdbc.get();
        if (operations == null || outcomes == null) {
            return null;
        }
        List<Map<String, Object>> found = operations.queryForList(
                "SELECT request_id, user_id, tenant_id FROM ctxa_ai_security_decision_observation WHERE observation_id = ?",
                observationId);
        if (found.isEmpty()) {
            return null;
        }
        Map<String, Object> row = found.get(0);
        String note = evaluation.note() == null ? null : evaluation.note().trim();
        String outcomeId = outcomes.evaluate(observationId, text(row.get("request_id")), text(row.get("user_id")),
                text(row.get("tenant_id")), evaluation.valid(), reason, reviewer, note == null || note.isEmpty() ? null : note);
        if (outcomeId == null) {
            throw new IllegalStateException("The evaluation could not be kept");
        }
        operations.update("""
                UPDATE ctxa_zt_review_queue
                   SET review_status = 'REVIEWED', reviewed_by = ?, reviewed_at = ?
                 WHERE observation_id = ?
                """, truncate(reviewer, 255), Timestamp.from(clock.instant()), observationId);
        log.info("[ZeroTrustConsole] Decision {} evaluated {} by {}", observationId,
                evaluation.valid() ? "valid" : "invalid", reviewer);
        return new EvaluationSaved(outcomeId, observationId, evaluation.valid() ? "EVALUATED_VALID" : "EVALUATED_INVALID");
    }

    // ----- helpers -----

    static String encodeCursor(Instant createdAt, String observationId) {
        String raw = createdAt.toString() + "|" + observationId;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    /** The position a cursor names, or null for none; a cursor that cannot be read starts from the top. */
    static Object[] decodeCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) {
            return null;
        }
        try {
            String raw = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
            int bar = raw.indexOf('|');
            if (bar <= 0) {
                return null;
            }
            return new Object[] {Timestamp.from(Instant.parse(raw.substring(0, bar))), raw.substring(bar + 1)};
        } catch (RuntimeException unreadable) {
            return null;
        }
    }

    private Map<String, Object> summary(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {
            });
        } catch (Exception unreadable) {
            log.warn("[ZeroTrustConsole] A decision summary could not be read", unreadable);
            return Map.of();
        }
    }

    private String message(String key, String fallback, Locale locale, Object... args) {
        return messages == null ? fallback : messages.getMessage(key, args, fallback, locale);
    }

    private static void equal(StringBuilder where, List<Object> args, String column, String value) {
        if (value != null) {
            where.append(" AND ").append(column).append(" = ?");
            args.add(value);
        }
    }

    private static String allowed(String value, Set<String> allowed) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String upper = value.trim().toUpperCase(Locale.ROOT);
        return allowed.contains(upper) ? upper : null;
    }

    private static String code(String value, int length) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String upper = value.trim().toUpperCase(Locale.ROOT);
        return upper.length() > length || !upper.matches("[A-Z0-9_]+") ? null : upper;
    }

    private static String likePrefix(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
    }

    private static <T> T first(List<T> values) {
        return values.isEmpty() ? null : values.get(0);
    }

    private static List<Map<String, Object>> listOfMaps(Object value) {
        List<Map<String, Object>> maps = new ArrayList<>();
        if (value instanceof List<?> list) {
            for (Object entry : list) {
                if (entry instanceof Map<?, ?> map) {
                    maps.add(copy(map));
                }
            }
        }
        return maps;
    }

    private static Map<String, Object> copy(Map<?, ?> map) {
        Map<String, Object> copy = new LinkedHashMap<>();
        map.forEach((key, entry) -> copy.put(String.valueOf(key), entry));
        return copy;
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }

    private static Long number(Object value) {
        return value instanceof Number number ? number.longValue() : null;
    }

    private static Integer integer(Object value) {
        return value instanceof Number number ? Integer.valueOf(number.intValue()) : null;
    }

    private static String truncate(String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }

    private static String instant(ResultSet rs, int column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant().toString();
    }

    private static String instantText(Object value) {
        return value instanceof Timestamp timestamp ? timestamp.toInstant().toString() : text(value);
    }
}
