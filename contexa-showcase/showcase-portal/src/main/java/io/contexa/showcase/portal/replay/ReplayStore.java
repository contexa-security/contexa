package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.replay.PairDefinition.SceneKind;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Recorded scenes (portal V4). A record points at its representative run; the step evidence is read from that run's
 * rows, never copied.
 */
public class ReplayStore {

    public record RecordRow(String recordId, String pairKey, SceneKind scene, String scenarioKey, int scenarioVersion,
                            String specHash, int repetitions, int agreeing, String representativeRunId,
                            String outcomeSignature, String status, Instant recordedAt, Instant publishedAt) {
    }

    public record RecordedRun(String runId, int repetition, String outcomeSignature) {
    }

    public record RunRow(String runId, String scenarioKey, String employeeKey, String templateId, String specHash,
                         Instant companyTime, String status, String forcedAction) {
    }

    public record ArmRow(String control, String requestId, String operation, String method, String path,
                         Integer httpStatus, String outcome, int deliveredItems, String ruleId, String reason,
                         Long elapsedMs, Instant companyTime, Instant sentAt, JsonNode stream) {
    }

    public record DecisionRow(String requestId, String finalAction, String proposedAction, Double riskScore,
                              Double confidence, boolean technicalFallback, boolean unresolved, String reasoning,
                              String applied, Long totalAnalysisMs, Instant decidedAt, JsonNode records,
                              JsonNode events) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public ReplayStore(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions, ObjectMapper json) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
    }

    public void save(RecordRow record, List<RecordedRun> runs) {
        transactions.executeWithoutResult(status -> {
            jdbc.update("""
                            insert into replay_record (record_id, pair_key, scene, scenario_key, scenario_version,
                                                       spec_hash, repetitions, agreeing, representative_run_id,
                                                       outcome_signature, status)
                            values (:id, :pair, :scene, :scenario, :version, :spec, :repetitions, :agreeing, :run,
                                    :signature, 'DRAFT')""",
                    new MapSqlParameterSource("id", record.recordId()).addValue("pair", record.pairKey())
                            .addValue("scene", record.scene().name()).addValue("scenario", record.scenarioKey())
                            .addValue("version", record.scenarioVersion()).addValue("spec", record.specHash())
                            .addValue("repetitions", record.repetitions()).addValue("agreeing", record.agreeing())
                            .addValue("run", record.representativeRunId())
                            .addValue("signature", record.outcomeSignature()));
            for (RecordedRun run : runs) {
                jdbc.update("""
                                insert into replay_run (record_id, run_id, repetition, outcome_signature)
                                values (:id, :run, :repetition, :signature)""",
                        new MapSqlParameterSource("id", record.recordId()).addValue("run", run.runId())
                                .addValue("repetition", run.repetition())
                                .addValue("signature", run.outcomeSignature()));
            }
        });
    }

    /** Publishes a record and retires the record it replaces for the same pair and scene. */
    public boolean publish(String recordId) {
        Optional<RecordRow> record = find(recordId);
        if (record.isEmpty() || "RETIRED".equals(record.get().status())) {
            return false;
        }
        transactions.executeWithoutResult(status -> {
            jdbc.update("""
                            update replay_record set status = 'RETIRED', retired_at = now()
                             where pair_key = :pair and scene = :scene and status = 'PUBLISHED' and record_id <> :id""",
                    new MapSqlParameterSource("pair", record.get().pairKey())
                            .addValue("scene", record.get().scene().name()).addValue("id", recordId));
            jdbc.update("update replay_record set status = 'PUBLISHED', published_at = now() where record_id = :id",
                    new MapSqlParameterSource("id", recordId));
        });
        return true;
    }

    public Optional<RecordRow> find(String recordId) {
        return jdbc.query("select * from replay_record where record_id = :id",
                new MapSqlParameterSource("id", recordId), (rs, n) -> record(rs)).stream().findFirst();
    }

    public Optional<RecordRow> published(String pairKey, SceneKind scene) {
        return jdbc.query("""
                        select * from replay_record where pair_key = :pair and scene = :scene and status = 'PUBLISHED'""",
                new MapSqlParameterSource("pair", pairKey).addValue("scene", scene.name()),
                (rs, n) -> record(rs)).stream().findFirst();
    }

    public List<RecordRow> list() {
        return jdbc.query("select * from replay_record order by recorded_at desc", (rs, n) -> record(rs));
    }

    public List<RecordedRun> runs(String recordId) {
        return jdbc.query("""
                        select run_id, repetition, outcome_signature from replay_run
                         where record_id = :id order by repetition""",
                new MapSqlParameterSource("id", recordId),
                (rs, n) -> new RecordedRun(rs.getString(1), rs.getInt(2), rs.getString(3)));
    }

    public Optional<String> specHashOf(String runId) {
        return jdbc.query("select spec_hash from run where run_id = :run", new MapSqlParameterSource("run", runId),
                (rs, n) -> rs.getString(1)).stream().findFirst();
    }

    public Optional<RunRow> run(String runId) {
        return jdbc.query("""
                        select run_id, scenario_key, employee_key, template_id, spec_hash, company_time, status,
                               forced_action
                          from run where run_id = :run""",
                new MapSqlParameterSource("run", runId),
                (rs, n) -> new RunRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), instant(rs.getTimestamp(6)), rs.getString(7), rs.getString(8)))
                .stream().findFirst();
    }

    /** Results of every control for one step, keyed by control. */
    public Map<String, ArmRow> arms(String runId, int stepNo) {
        Map<String, ArmRow> arms = new LinkedHashMap<>();
        jdbc.query("""
                        select control, request_id, operation, method, path, http_status, outcome, delivered_items,
                               rule_id, reason, elapsed_ms, company_time, sent_at, stream::text
                          from run_arm_result where run_id = :run and step_no = :step""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo), rs -> {
                    arms.put(rs.getString(1), new ArmRow(rs.getString(1), rs.getString(2), rs.getString(3),
                            rs.getString(4), rs.getString(5), (Integer) rs.getObject(6), rs.getString(7), rs.getInt(8),
                            rs.getString(9), rs.getString(10), (Long) rs.getObject(11), instant(rs.getTimestamp(12)),
                            instant(rs.getTimestamp(13)), read(rs.getString(14))));
                });
        return arms;
    }

    public int stepCount(String runId) {
        Integer steps = jdbc.queryForObject("select coalesce(max(step_no), 0) from run_arm_result where run_id = :run",
                new MapSqlParameterSource("run", runId), Integer.class);
        return steps == null ? 0 : steps;
    }

    public Optional<DecisionRow> decision(String runId, int stepNo) {
        return jdbc.query("""
                        select request_id, final_action, proposed_action, risk_score, confidence, technical_fallback,
                               unresolved, reasoning, applied, total_analysis_ms, decided_at, records::text, events::text
                          from run_decision where run_id = :run and step_no = :step""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo),
                (rs, n) -> new DecisionRow(rs.getString(1), rs.getString(2), rs.getString(3),
                        (Double) rs.getObject(4), (Double) rs.getObject(5), Boolean.TRUE.equals(rs.getObject(6)),
                        Boolean.TRUE.equals(rs.getObject(7)), rs.getString(8), rs.getString(9),
                        (Long) rs.getObject(10), instant(rs.getTimestamp(11)), read(rs.getString(12)),
                        read(rs.getString(13))))
                .stream().findFirst();
    }

    /** The rule controls' own decision records (with the facts they looked up) of a run, keyed by request ID. */
    public Map<String, JsonNode> ruleDecisions(String runId) {
        Map<String, JsonNode> decisions = new LinkedHashMap<>();
        jdbc.query("select rule_decisions::text from run_business_evidence where run_id = :run",
                new MapSqlParameterSource("run", runId), rs -> {
                    for (JsonNode decision : read(rs.getString(1))) {
                        decisions.put(decision.path("request_id").asText(), decision);
                    }
                });
        return decisions;
    }

    private RecordRow record(ResultSet rs) throws SQLException {
        return new RecordRow(rs.getString("record_id"), rs.getString("pair_key"),
                SceneKind.valueOf(rs.getString("scene")), rs.getString("scenario_key"), rs.getInt("scenario_version"),
                rs.getString("spec_hash"), rs.getInt("repetitions"), rs.getInt("agreeing"),
                rs.getString("representative_run_id"), rs.getString("outcome_signature"), rs.getString("status"),
                instant(rs.getTimestamp("recorded_at")), instant(rs.getTimestamp("published_at")));
    }

    private JsonNode read(String text) {
        if (text == null) {
            return json.createArrayNode();
        }
        try {
            return json.readTree(text);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable stored JSON", e);
        }
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
