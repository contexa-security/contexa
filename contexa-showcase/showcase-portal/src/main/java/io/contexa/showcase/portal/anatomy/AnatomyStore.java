package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder.StoredCall;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder.StoredDecision;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder.Surroundings;
import io.contexa.showcase.portal.scoring.RunScores;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Reads the stored records a verdict anatomy is built from, builds it with {@link AnatomyBuilder}, keeps a copy
 * (run_decision_anatomy, so the anatomy stays after the 90-day prompt texts are gone) and serves the stored model
 * call texts while they are kept (docs/showcase/데모-재설계.md 5.1, 5.2).
 */
public class AnatomyStore {

    /** The texts of one stored model call, for the visitor's "raw" view. */
    public record Exchange(int callNo, String model, String systemPrompt, String userPrompt, String answer,
                           JsonNode requestOptions, String providerResponse, String finishReason, Long promptTokens,
                           Long completionTokens, Long reasoningTokens, int maskedPlaces, Instant capturedAt) {
    }

    /**
     * @param kept    false when the run exists but no text of the step is stored
     * @param missing why, when not kept: {@link #PAST_RETENTION} or {@link #NOT_COLLECTED}; null when kept
     */
    public record Exchanges(String runId, int stepNo, boolean kept, String missing, List<Exchange> calls) {
    }

    /** The run started longer ago than the text retention, so the daily retention job deleted its texts. */
    public static final String PAST_RETENTION = "PAST_RETENTION";
    /**
     * The run is younger than the text retention and has no texts: they were never captured (runs before the capture
     * began, or a decision made without a model call).
     */
    public static final String NOT_COLLECTED = "NOT_COLLECTED";

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };
    private static final List<String> JSON_COLUMNS = List.of("block_record", "model_settings");

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;
    private final AnatomyBuilder builder;
    private final RunScores scores;
    private final Duration textRetention;
    private final Clock clock;

    /**
     * @param textRetention how long model call texts are kept (the retention job's period for them)
     */
    public AnatomyStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json, RunScores scores, Duration textRetention,
                        Clock clock) {
        this.jdbc = jdbc;
        this.json = json;
        this.builder = new AnatomyBuilder(json);
        this.scores = scores;
        this.textRetention = textRetention;
        this.clock = clock;
    }

    /**
     * Why a step has no stored texts. The retention job deletes texts captured before the cut-off; a run's texts are
     * captured within its run, so a run that started before the cut-off has had them deleted.
     */
    static String missing(Instant runStartedAt, Instant now, Duration textRetention) {
        return runStartedAt.isBefore(now.minus(textRetention)) ? PAST_RETENTION : NOT_COLLECTED;
    }

    /** The stored anatomy of a step, built and stored first when it is missing or of an older builder version. */
    public Optional<DecisionAnatomy> anatomy(String runId, int stepNo) {
        Optional<StoredStep> step = step(runId, stepNo);
        if (step.isEmpty()) {
            return Optional.empty();
        }
        Optional<DecisionAnatomy> stored = stored(step.get().decision().requestId());
        if (stored.isPresent() && stored.get().builderVersion() == AnatomyBuilder.VERSION) {
            return stored;
        }
        return Optional.of(buildAndStore(step.get()));
    }

    /** Builds and stores the anatomy of every step of a run that has a decision row (the run's end). */
    public void buildAll(String runId) {
        List<Integer> steps = jdbc.queryForList(
                "select step_no from run_decision where run_id = :run order by step_no",
                new MapSqlParameterSource("run", runId), Integer.class);
        for (int stepNo : steps) {
            step(runId, stepNo).ifPresent(this::buildAndStore);
        }
    }

    public Optional<Exchanges> exchanges(String runId, int stepNo) {
        Boolean exists = jdbc.queryForObject(
                "select exists (select 1 from run_decision where run_id = :run and step_no = :step)",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo), Boolean.class);
        if (!Boolean.TRUE.equals(exists)) {
            return Optional.empty();
        }
        List<Exchange> calls = jdbc.query("""
                        select e.call_no, e.model, p.prompt_text, e.user_prompt, e.answer, e.request_options::text,
                               e.provider_response, e.finish_reason, e.prompt_tokens, e.completion_tokens,
                               e.reasoning_tokens, e.masked_places, e.captured_at
                          from run_model_exchange e
                          left join run_system_prompt p on p.system_prompt_sha256 = e.system_prompt_sha256
                         where e.run_id = :run and e.step_no = :step
                         order by e.call_no""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo),
                (rs, n) -> new Exchange(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), readTree(rs.getString(6)), rs.getString(7), rs.getString(8),
                        longOrNull(rs, 9), longOrNull(rs, 10), longOrNull(rs, 11), rs.getInt(12),
                        rs.getTimestamp(13).toInstant()));
        if (!calls.isEmpty()) {
            return Optional.of(new Exchanges(runId, stepNo, true, null, calls));
        }
        Timestamp started = jdbc.queryForObject("select started_at from run where run_id = :run",
                new MapSqlParameterSource("run", runId), Timestamp.class);
        return Optional.of(new Exchanges(runId, stepNo, false,
                missing(started.toInstant(), clock.instant(), textRetention), calls));
    }

    private record StoredStep(String runId, int stepNo, String operation, StoredDecision decision,
                              JsonNode definition, String definitionSha, String templateId) {
    }

    private Optional<StoredStep> step(String runId, int stepNo) {
        List<StoredStep> rows = jdbc.query("""
                        select d.request_id::text, d.final_action, d.proposed_action, d.risk_score, d.confidence,
                               d.reasoning, d.mitre, d.unresolved, d.failure_type, d.fallback_category, d.applied,
                               d.llm_latency_ms, d.total_analysis_ms, d.records::text, d.events::text,
                               r.scenario_definition::text, r.scenario_sha256,
                               (select a.operation from run_arm_result a
                                 where a.run_id = d.run_id and a.step_no = d.step_no and a.control = 'D'),
                               r.template_id
                          from run_decision d join run r on r.run_id = d.run_id
                         where d.run_id = :run and d.step_no = :step""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo),
                (rs, n) -> new StoredStep(runId, stepNo, rs.getString(18), new StoredDecision(rs.getString(1),
                        rs.getString(2), rs.getString(3), doubleOrNull(rs, 4), doubleOrNull(rs, 5), rs.getString(6),
                        rs.getString(7), rs.getBoolean(8), rs.getString(9), rs.getString(10), rs.getString(11),
                        longOrNull(rs, 12), longOrNull(rs, 13), readTree(rs.getString(14)),
                        readTree(rs.getString(15))), readTree(rs.getString(16)), rs.getString(17),
                        rs.getString(19)));
        return rows.stream().findFirst();
    }

    private DecisionAnatomy buildAndStore(StoredStep step) {
        List<StoredCall> calls = jdbc.query("""
                        select call_no, model, request_options::text, finish_reason, prompt_tokens, completion_tokens,
                               reasoning_tokens, elapsed_ms, success, failure, http_status, answer, masked_places,
                               finished_at, system_prompt_sha256
                          from run_model_exchange where request_id = :request order by call_no""",
                new MapSqlParameterSource("request", UUID.fromString(step.decision().requestId())),
                (rs, n) -> new StoredCall(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        longOrNull(rs, 5), longOrNull(rs, 6), longOrNull(rs, 7), longOrNull(rs, 8),
                        rs.getBoolean(9), rs.getString(10), (Integer) rs.getObject(11), rs.getString(12),
                        rs.getInt(13), instantOrNull(rs.getTimestamp(14)), rs.getString(15)));
        List<String> prompts = jdbc.queryForList("""
                        select p.prompt_text from run_model_exchange e
                          join run_system_prompt p on p.system_prompt_sha256 = e.system_prompt_sha256
                         where e.request_id = :request order by e.call_no desc limit 1""",
                new MapSqlParameterSource("request", UUID.fromString(step.decision().requestId())), String.class);
        List<String> userPrompts = jdbc.queryForList("""
                        select user_prompt from run_model_exchange
                         where request_id = :request order by call_no desc limit 1""",
                new MapSqlParameterSource("request", UUID.fromString(step.decision().requestId())), String.class);
        Surroundings around = new Surroundings(scores.score(step.runId()).orElse(null), step.definition(),
                step.definitionSha(), template(step.templateId()), learning(step.runId()),
                row("select * from run_challenge where run_id = :run and step_no = :step", step),
                row("select * from run_release where run_id = :run and step_no = :step", step),
                userPrompts.isEmpty() ? null : userPrompts.get(0));
        DecisionAnatomy anatomy = builder.build(step.runId(), step.stepNo(), step.operation(), step.decision(), calls,
                prompts.isEmpty() ? null : prompts.get(0), around);
        jdbc.update("""
                        insert into run_decision_anatomy (request_id, anatomy, builder_version, built_at)
                        values (:request, cast(:anatomy as jsonb), :version, :at)
                        on conflict (request_id) do update set anatomy = excluded.anatomy,
                            builder_version = excluded.builder_version, built_at = excluded.built_at""",
                new MapSqlParameterSource("request", UUID.fromString(step.decision().requestId()))
                        .addValue("anatomy", write(anatomy)).addValue("version", AnatomyBuilder.VERSION)
                        .addValue("at", Timestamp.from(Instant.now())));
        return anatomy;
    }

    /** The template row the run was cloned from, without its snapshot (the learned state itself). */
    private Map<String, Object> template(String templateId) {
        if (templateId == null) {
            return Map.of();
        }
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select template_id, employee_key, status, chat_model, embedding_model, model_settings,
                               requests, allowed, baseline_update_count, work_profile_observations, memory_documents,
                               learned_under, identity_checks, created_at, ready_at, retired_at
                          from engine_template where template_id = :template""",
                new MapSqlParameterSource("template", templateId));
        return rows.isEmpty() ? Map.of() : plain(rows.get(0));
    }

    private Map<String, Object> learning(String runId) {
        List<String> rows = jdbc.queryForList("select learning::text from run_learning where run_id = :run",
                new MapSqlParameterSource("run", runId), String.class);
        if (rows.isEmpty()) {
            return Map.of();
        }
        try {
            return json.readValue(rows.get(0), MAP);
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable stored run learning", e);
        }
    }

    /** One row of the step as stored, JSON columns read as JSON; null without a row. */
    private Map<String, Object> row(String sql, StoredStep step) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql,
                new MapSqlParameterSource("run", step.runId()).addValue("step", step.stepNo()));
        return rows.isEmpty() ? null : plain(rows.get(0));
    }

    private Map<String, Object> plain(Map<String, Object> row) {
        Map<String, Object> copy = new LinkedHashMap<>();
        row.forEach((column, value) -> {
            if (value instanceof Timestamp timestamp) {
                copy.put(column, timestamp.toInstant().toString());
            } else if (value instanceof UUID uuid) {
                copy.put(column, uuid.toString());
            } else if (JSON_COLUMNS.contains(column) && value != null) {
                copy.put(column, readTree(value.toString()));
            } else {
                copy.put(column, value);
            }
        });
        return copy;
    }

    private static Instant instantOrNull(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private Optional<DecisionAnatomy> stored(String requestId) {
        List<String> rows = jdbc.queryForList(
                "select anatomy::text from run_decision_anatomy where request_id = :request",
                new MapSqlParameterSource("request", UUID.fromString(requestId)), String.class);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(json.readValue(rows.get(0), DecisionAnatomy.class));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private JsonNode readTree(String text) {
        if (text == null) {
            return null;
        }
        try {
            return json.readTree(text);
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable stored JSON", e);
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable anatomy", e);
        }
    }

    private static Long longOrNull(ResultSet rs, int column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static Double doubleOrNull(ResultSet rs, int column) throws SQLException {
        double value = rs.getDouble(column);
        return rs.wasNull() ? null : value;
    }
}
