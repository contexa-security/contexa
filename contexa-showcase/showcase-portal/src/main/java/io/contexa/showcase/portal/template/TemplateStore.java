package io.contexa.showcase.portal.template;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Learned templates in the portal database ({@code engine_template}), the source every run is cloned from. The
 * engine keeps state in memory in standalone mode, so the snapshot here survives an engine restart (ADR-03, ADR-06).
 */
public class TemplateStore {

    public record ReadyTemplate(String templateId, String employeeKey, JsonNode snapshot, Instant readyAt) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;

    public TemplateStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /**
     * @param learnedUnder {@link TemplateVersions} key of the versions in force while the template is learned
     */
    public void start(String templateId, String employeeKey, long seed, LocalDate anchor, String companySha,
                      int attempt, String chatModel, String embeddingModel, String learnedUnder) {
        jdbc.update("""
                        insert into engine_template (template_id, employee_key, company_seed, company_anchor,
                                                     company_sha256, status, attempt, chat_model, embedding_model,
                                                     learned_under)
                        values (:id, :employee, :seed, :anchor, :sha, 'LEARNING', :attempt, :chat, :embedding,
                                :learnedUnder)""",
                new MapSqlParameterSource("id", templateId).addValue("employee", employeeKey).addValue("seed", seed)
                        .addValue("anchor", Date.valueOf(anchor)).addValue("sha", companySha)
                        .addValue("attempt", attempt).addValue("chat", chatModel).addValue("embedding", embeddingModel)
                        .addValue("learnedUnder", learnedUnder));
    }

    public void step(String templateId, int stepNo, String requestId, String operation, String targetKey,
                     Instant companyTime, Integer httpStatus, String finalAction, Boolean technicalFallback,
                     boolean unresolved, long waitedMs) {
        jdbc.update("""
                        insert into template_step (template_id, step_no, request_id, operation, target_key, company_time,
                                                   http_status, final_action, technical_fallback, unresolved,
                                                   waited_ms)
                        values (:id, :step, :request, :operation, :target, :time, :status, :action, :fallback,
                                :unresolved, :waited)""",
                new MapSqlParameterSource("id", templateId).addValue("step", stepNo)
                        .addValue("request", UUID.fromString(requestId)).addValue("operation", operation)
                        .addValue("target", targetKey).addValue("time", Timestamp.from(companyTime))
                        .addValue("status", httpStatus).addValue("action", finalAction)
                        .addValue("fallback", technicalFallback).addValue("unresolved", unresolved)
                        .addValue("waited", waitedMs));
        jdbc.update("""
                        update engine_template set requests = requests + 1,
                               allowed = allowed + case when :action = 'ALLOW' and not :unresolved then 1 else 0 end
                         where template_id = :id""",
                new MapSqlParameterSource("id", templateId).addValue("action", finalAction)
                        .addValue("unresolved", unresolved));
    }

    public void ready(String templateId, JsonNode snapshot, Integer stoppedAtStep) {
        jdbc.update("""
                        update engine_template set status = 'READY', snapshot = cast(:snapshot as jsonb),
                               stopped_at_step = :stopped,
                               baseline_update_count = :updates, work_profile_observations = :observations,
                               memory_documents = :documents, ready_at = now()
                         where template_id = :id""",
                new MapSqlParameterSource("id", templateId).addValue("snapshot", write(snapshot))
                        .addValue("stopped", stoppedAtStep)
                        .addValue("updates", snapshot.path("baselineUpdateCount").asLong())
                        .addValue("observations", snapshot.path("workProfileObservations").size())
                        .addValue("documents", snapshot.path("behaviourDocuments").size()));
        // The new template replaces the employee's earlier ones; retired templates are deleted after the retention
        // period once no kept run refers to them (RetentionJob).
        jdbc.update("""
                        update engine_template set status = 'RETIRED', retired_at = now()
                         where status = 'READY' and template_id <> :id
                           and employee_key = (select employee_key from engine_template where template_id = :id)""",
                new MapSqlParameterSource("id", templateId));
    }

    public void failed(String templateId, String reason) {
        jdbc.update("update engine_template set status = 'FAILED', failure = :reason where template_id = :id",
                new MapSqlParameterSource("id", templateId)
                        .addValue("reason", reason == null || reason.length() <= 500 ? reason : reason.substring(0, 500)));
    }

    /** The employee's READY template learned under the given versions, the only kind a run may clone. */
    public Optional<ReadyTemplate> current(String employeeKey, String learnedUnder) {
        List<ReadyTemplate> rows = jdbc.query("""
                        select template_id, employee_key, snapshot::text, ready_at from engine_template
                         where employee_key = :employee and status = 'READY' and learned_under = :learnedUnder
                         order by ready_at desc limit 1""",
                new MapSqlParameterSource("employee", employeeKey).addValue("learnedUnder", learnedUnder),
                (rs, n) -> new ReadyTemplate(rs.getString(1), rs.getString(2), read(rs.getString(3)),
                        rs.getTimestamp(4).toInstant()));
        return rows.stream().findFirst();
    }

    /** Whether an attempt for the employee started after {@code since} is still learning. */
    public boolean learningSince(String employeeKey, Instant since) {
        Integer count = jdbc.queryForObject("""
                        select count(*) from engine_template
                         where employee_key = :employee and status = 'LEARNING' and created_at > :since""",
                new MapSqlParameterSource("employee", employeeKey).addValue("since", Timestamp.from(since)),
                Integer.class);
        return count != null && count > 0;
    }

    /** Whether an attempt for the employee failed after {@code since}. */
    public boolean failedSince(String employeeKey, Instant since) {
        Integer count = jdbc.queryForObject("""
                        select count(*) from engine_template
                         where employee_key = :employee and status = 'FAILED' and created_at > :since""",
                new MapSqlParameterSource("employee", employeeKey).addValue("since", Timestamp.from(since)),
                Integer.class);
        return count != null && count > 0;
    }

    public Optional<ReadyTemplate> latestReady(String employeeKey) {
        List<ReadyTemplate> rows = jdbc.query("""
                        select template_id, employee_key, snapshot::text, ready_at from engine_template
                         where employee_key = :employee and status = 'READY'
                         order by ready_at desc limit 1""",
                new MapSqlParameterSource("employee", employeeKey),
                (rs, n) -> new ReadyTemplate(rs.getString(1), rs.getString(2), read(rs.getString(3)),
                        rs.getTimestamp(4).toInstant()));
        return rows.stream().findFirst();
    }

    public List<Map<String, Object>> list() {
        return jdbc.queryForList("""
                select template_id, employee_key, status, attempt, requests, allowed, baseline_update_count,
                       work_profile_observations, memory_documents, stopped_at_step, failure, company_anchor,
                       chat_model, learned_under, created_at, ready_at, retired_at
                  from engine_template order by created_at desc""", new MapSqlParameterSource());
    }

    public List<Map<String, Object>> steps(String templateId) {
        return jdbc.queryForList("""
                select step_no, request_id, operation, target_key, company_time, http_status, final_action,
                       technical_fallback, unresolved, waited_ms
                  from template_step where template_id = :id order by step_no""",
                new MapSqlParameterSource("id", templateId));
    }

    private JsonNode read(String text) {
        try {
            return json.readTree(text);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable template snapshot", e);
        }
    }

    private String write(JsonNode node) {
        try {
            return json.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable template snapshot", e);
        }
    }
}
