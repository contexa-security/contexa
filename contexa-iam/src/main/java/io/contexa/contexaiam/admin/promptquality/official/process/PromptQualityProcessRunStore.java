package io.contexa.contexaiam.admin.promptquality.official.process;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

final class PromptQualityProcessRunStore {
    private static final int BUSINESS_KEY_LIMIT = 128;
    private static final int STATE_LIMIT = 32;
    private static final int STEP_CODE_LIMIT = 96;
    private static final int STATE_DIMENSION_LIMIT = 96;
    private static final int STATE_CODE_LIMIT = 128;
    private static final int TENANT_ID_LIMIT = 128;
    private static final int RESOURCE_ID_LIMIT = 500;
    private static final int RESOURCE_URL_LIMIT = 1000;
    private static final int HTTP_METHOD_LIMIT = 24;
    private static final int ACTOR_LIMIT = 128;
    private static final int EVENT_TYPE_LIMIT = 96;
    private static final int EVIDENCE_REF_LIMIT = 500;
    private static final int ROUTE_LIMIT = 1000;
    private static final int SUMMARY_LIMIT = 3000;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    PromptQualityProcessRunStore(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }
    long ensureRun(PromptQualityProcessScope scope, String actor) {
        if (scope == null || !StringUtils.hasText(scope.resourceId())) {
            throw new IllegalArgumentException("Prompt quality process scope requires resourceId.");
        }
        long processId = processId(PromptQualityProcessCodes.MAIN);
        String businessKey = businessKey(scope);
        List<Long> existing = jdbcTemplate.query(
                "select id from prompt_quality_process_run where process_id = ? and business_key = ?",
                (rs, rowNum) -> rs.getLong("id"),
                processId,
                businessKey);
        if (!existing.isEmpty()) {
            long runId = existing.get(0);
            initializePendingSteps(runId, actor);
            return runId;
        }
        jdbcTemplate.update(
                """
                        insert into prompt_quality_process_run
                            (process_id, tenant_id, resource_id, resource_url, http_method, business_key,
                             state, started_at, started_by, payload_json, created_at, updated_at)
                        values (?, ?, ?, ?, ?, ?, ?, current_timestamp, ?, ?, current_timestamp, current_timestamp)
                        """,
                processId,
                boundedValue(scope.tenantId(), TENANT_ID_LIMIT),
                boundedValue(scope.resourceId(), RESOURCE_ID_LIMIT),
                boundedValue(scope.resourceUrl(), RESOURCE_URL_LIMIT),
                boundedValue(scope.httpMethod(), HTTP_METHOD_LIMIT),
                businessKey,
                PromptQualityProcessCodes.RUNNING,
                boundedValue(actor, ACTOR_LIMIT),
                json(payload(scope)));
        long runId = jdbcTemplate.query(
                        "select id from prompt_quality_process_run where process_id = ? and business_key = ?",
                        (rs, rowNum) -> rs.getLong("id"),
                        processId,
                        businessKey)
                .stream()
                .findFirst()
                .orElseThrow();
        initializePendingSteps(runId, actor);
        recordHistory(runId, null, null, null, PromptQualityProcessCodes.RUNNING,
                null, null, "PROCESS_STAGE", PromptQualityProcessCodes.PROTECTABLE_RESOURCES,
                scope.resourceId(), actor, "PQA main process started.");
        recordEvent(runId, null, "PROCESS_STARTED",
                eventPayload(PromptQualityProcessCodes.MAIN, PromptQualityProcessCodes.RUNNING,
                        "PROCESS_STAGE", PromptQualityProcessCodes.PROTECTABLE_RESOURCES,
                        scope.resourceId(), "PQA main process started."));
        return runId;
    }

    private void initializePendingSteps(long runId, String actor) {
        for (String stepCode : PromptQualityProcessCodes.ORDERED_STEPS) {
            long stepProcessId = processId(stepCode);
            List<Long> existing = jdbcTemplate.query(
                    "select id from prompt_quality_process_step_run where run_id = ? and step_process_id = ?",
                    (rs, rowNum) -> rs.getLong("id"),
                    runId,
                    stepProcessId);
            if (!existing.isEmpty()) {
                continue;
            }
            jdbcTemplate.update(
                    """
                            insert into prompt_quality_process_step_run
                                (run_id, step_process_id, sequence_no, state, executor, created_at, updated_at)
                            values (?, ?, ?, ?, ?, current_timestamp, current_timestamp)
                            """,
                    runId,
                    stepProcessId,
                    sequenceNo(stepProcessId),
                    PromptQualityProcessCodes.PENDING,
                    boundedValue(actor, ACTOR_LIMIT));
        }
    }

    StepHandle ensureStepRun(long runId, String stepCode, String actor) {
        long stepProcessId = processId(stepCode);
        List<Long> existing = jdbcTemplate.query(
                "select id from prompt_quality_process_step_run where run_id = ? and step_process_id = ?",
                (rs, rowNum) -> rs.getLong("id"),
                runId,
                stepProcessId);
        if (!existing.isEmpty()) {
            return new StepHandle(existing.get(0), false);
        }
        int sequenceNo = sequenceNo(stepProcessId);
        jdbcTemplate.update(
                """
                        insert into prompt_quality_process_step_run
                            (run_id, step_process_id, sequence_no, state, started_at, executor, created_at, updated_at)
                        values (?, ?, ?, ?, current_timestamp, ?, current_timestamp, current_timestamp)
                        """,
                runId,
                stepProcessId,
                sequenceNo,
                PromptQualityProcessCodes.RUNNING,
                boundedValue(actor, ACTOR_LIMIT));
        Long id = jdbcTemplate.query(
                        "select id from prompt_quality_process_step_run where run_id = ? and step_process_id = ?",
                        (rs, rowNum) -> rs.getLong("id"),
                        runId,
                        stepProcessId)
                .stream()
                .findFirst()
                .orElseThrow();
        return new StepHandle(id, true);
    }

    private long processId(String code) {
        return jdbcTemplate.query(
                        "select id from prompt_quality_process_definition where code = ? and is_active = true",
                        (rs, rowNum) -> rs.getLong("id"),
                        code)
                .stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Prompt quality process definition is missing: " + code));
    }

    private int sequenceNo(long processId) {
        return jdbcTemplate.query(
                        "select sequence_no from prompt_quality_process_definition where id = ?",
                        (rs, rowNum) -> rs.getInt("sequence_no"),
                        processId)
                .stream()
                .findFirst()
                .orElse(0);
    }

    boolean sequentialTransitionAllowed(long runId, String stepCode) {
        Integer count = jdbcTemplate.queryForObject(
                """
                        select count(*)
                          from prompt_quality_process_step_run current_step
                          join prompt_quality_process_definition current_definition
                            on current_definition.id = current_step.step_process_id
                          join prompt_quality_process_step_run previous_step
                            on previous_step.run_id = current_step.run_id
                          join prompt_quality_process_definition previous_definition
                            on previous_definition.id = previous_step.step_process_id
                         where current_step.run_id = ?
                           and current_definition.code = ?
                           and previous_definition.sequence_no < current_definition.sequence_no
                           and previous_step.state <> 'COMPLETED'
                        """,
                Integer.class,
                runId,
                stepCode);
        return count == null || count == 0;
    }

    boolean allStepsCompleted(long runId) {
        Integer count = jdbcTemplate.queryForObject(
                """
                        select count(*)
                          from prompt_quality_process_step_run
                         where run_id = ?
                           and state <> 'COMPLETED'
                        """,
                Integer.class,
                runId);
        return count != null && count == 0;
    }

    void recordSequenceBlocked(long runId, Long stepRunId, String stepCode, String actor, String reason) {
        String blockedBy = firstIncompleteStepBefore(runId, stepCode);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("stepCode", value(stepCode));
        payload.put("blockedByStepCode", value(blockedBy));
        payload.put("executionState", "SEQUENCE_BLOCKED");
        payload.put("reason", value(reason));
        payload.put("message", "Process stage transition was blocked because an earlier stage is not completed.");
        recordEvent(runId, stepRunId, "STEP_SEQUENCE_BLOCKED", payload);
    }

    private String firstIncompleteStepBefore(long runId, String stepCode) {
        return jdbcTemplate.query(
                        """
                                select previous_definition.code
                                  from prompt_quality_process_step_run current_step
                                  join prompt_quality_process_definition current_definition
                                    on current_definition.id = current_step.step_process_id
                                  join prompt_quality_process_step_run previous_step
                                    on previous_step.run_id = current_step.run_id
                                  join prompt_quality_process_definition previous_definition
                                    on previous_definition.id = previous_step.step_process_id
                                 where current_step.run_id = ?
                                   and current_definition.code = ?
                                   and previous_definition.sequence_no < current_definition.sequence_no
                                   and previous_step.state <> 'COMPLETED'
                                 order by previous_definition.sequence_no asc
                                """,
                        (rs, rowNum) -> rs.getString("code"),
                        runId,
                        stepCode)
                .stream()
                .findFirst()
                .orElse(null);
    }

    void updateRun(
            long runId,
            String executionState,
            String currentStepCode,
            String domainStateDimension,
            String domainStateCode,
            String errorMessage) {
        jdbcTemplate.update(
                """
                        update prompt_quality_process_run
                           set state = case
                                   when state = 'COMPLETED' and ? <> 'COMPLETED' then state
                                   else ?
                               end,
                               current_step_code = ?,
                               current_state_dimension = ?,
                               current_state_code = ?,
                               ended_at = case
                                   when ? = 'COMPLETED' and ended_at is null then current_timestamp
                                   else ended_at
                               end,
                               error_message = case
                                   when state = 'COMPLETED' and ? <> 'COMPLETED' then error_message
                                   else ?
                               end,
                               updated_at = current_timestamp
                         where id = ?
                        """,
                executionState,
                executionState,
                boundedValue(currentStepCode, STEP_CODE_LIMIT),
                boundedNormalized(domainStateDimension, STATE_DIMENSION_LIMIT),
                boundedNormalized(domainStateCode, STATE_CODE_LIMIT),
                executionState,
                executionState,
                errorMessage,
                runId);
    }

    void updateStep(
            long stepRunId,
            String executionState,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String summary,
            String nextAction,
            String resultJson,
            String errorMessage) {
        jdbcTemplate.update(
                """
                        update prompt_quality_process_step_run
                           set state = ?,
                               domain_state_dimension = ?,
                               domain_state_code = ?,
                               evidence_ref = ?,
                               route = ?,
                               summary = ?,
                               next_action = ?,
                               result_json = ?,
                               error_message = ?,
                               started_at = case
                                   when ? <> 'PENDING' and started_at is null then current_timestamp
                                   else started_at
                               end,
                               ended_at = case when ? in ('COMPLETED', 'FAILED') then current_timestamp else null end,
                               updated_at = current_timestamp
                         where id = ?
                        """,
                boundedValue(executionState, STATE_LIMIT),
                boundedNormalized(domainStateDimension, STATE_DIMENSION_LIMIT),
                boundedNormalized(domainStateCode, STATE_CODE_LIMIT),
                boundedValue(evidenceRef, EVIDENCE_REF_LIMIT),
                boundedValue(route, ROUTE_LIMIT),
                boundedValue(summary, SUMMARY_LIMIT),
                boundedValue(nextAction, SUMMARY_LIMIT),
                resultJson,
                errorMessage,
                executionState,
                executionState,
                stepRunId);
    }

    void recordHistory(
            long runId,
            Long stepRunId,
            String stepCode,
            String fromState,
            String toState,
            String fromDomainStateDimension,
            String fromDomainStateCode,
            String toDomainStateDimension,
            String toDomainStateCode,
            String evidenceRef,
            String actor,
            String reason) {
        jdbcTemplate.update(
                """
                        insert into prompt_quality_process_state_history
                            (run_id, step_run_id, process_code, step_code,
                             from_state, to_state,
                             from_domain_state_dimension, from_domain_state_code,
                             to_domain_state_dimension, to_domain_state_code,
                             evidence_ref, changed_at, changed_by, reason)
                        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, current_timestamp, ?, ?)
                        """,
                runId,
                stepRunId,
                boundedValue(PromptQualityProcessCodes.MAIN, STEP_CODE_LIMIT),
                boundedValue(stepCode, STEP_CODE_LIMIT),
                boundedValue(fromState, STATE_LIMIT),
                boundedValue(toState, STATE_LIMIT),
                boundedNormalized(fromDomainStateDimension, STATE_DIMENSION_LIMIT),
                boundedNormalized(fromDomainStateCode, STATE_CODE_LIMIT),
                boundedNormalized(toDomainStateDimension, STATE_DIMENSION_LIMIT),
                boundedNormalized(toDomainStateCode, STATE_CODE_LIMIT),
                boundedValue(evidenceRef, EVIDENCE_REF_LIMIT),
                boundedValue(actor, ACTOR_LIMIT),
                value(reason));
    }

    void recordEvent(long runId, Long stepRunId, String type, Map<String, Object> payload) {
        jdbcTemplate.update(
                """
                        insert into prompt_quality_process_event
                            (run_id, step_run_id, type, payload_json, occurred_at)
                        values (?, ?, ?, ?, current_timestamp)
                        """,
                runId,
                stepRunId,
                boundedValue(type, EVENT_TYPE_LIMIT),
                json(payload));
    }

    StepState stepState(long stepRunId) {
        return jdbcTemplate.query(
                        """
                                select state, domain_state_dimension, domain_state_code
                                  from prompt_quality_process_step_run
                                 where id = ?
                                """,
                        (rs, rowNum) -> new StepState(
                                rs.getString("state"),
                                rs.getString("domain_state_dimension"),
                                rs.getString("domain_state_code")),
                        stepRunId)
                .stream()
                .findFirst()
                .orElse(new StepState(null, null, null));
    }

    RunState runState(long runId) {
        return jdbcTemplate.query(
                        """
                                select state, current_state_dimension, current_state_code
                                  from prompt_quality_process_run
                                 where id = ?
                                """,
                        (rs, rowNum) -> new RunState(
                                rs.getString("state"),
                                rs.getString("current_state_dimension"),
                                rs.getString("current_state_code")),
                        runId)
                .stream()
                .findFirst()
                .orElse(new RunState(null, null, null));
    }

    String json(Map<String, Object> value) {
        if (value == null || value.isEmpty()) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (Exception ignored) {
            return "{}";
        }
    }

    private Map<String, Object> payload(PromptQualityProcessScope scope) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("promptContractVersion", value(scope.promptContractVersion()));
        payload.put("modelProfile", value(scope.modelProfile()));
        payload.put("verifierVersion", value(scope.verifierVersion()));
        return payload;
    }

    Map<String, Object> eventPayload(
            String stepCode,
            String executionState,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String reason) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("stepCode", value(stepCode));
        payload.put("executionState", value(executionState));
        payload.put("domainStateDimension", normalize(domainStateDimension));
        payload.put("domainStateCode", normalize(domainStateCode));
        payload.put("evidenceRef", value(evidenceRef));
        payload.put("reason", value(reason));
        return payload;
    }

    static String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase() : null;
    }

    static String value(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    static String businessKey(PromptQualityProcessScope scope) {
        return boundedValue(scope == null ? null : scope.businessKey(), BUSINESS_KEY_LIMIT);
    }

    static String boundedNormalized(String value, int limit) {
        return boundedValue(normalize(value), limit);
    }

    static String boundedValue(String value, int limit) {
        String normalized = StringUtils.hasText(value) ? value.trim() : null;
        if (normalized == null || limit <= 0 || normalized.length() <= limit) {
            return normalized;
        }
        String hash = shortHash(normalized);
        int prefixLength = Math.max(1, limit - hash.length() - 1);
        return normalized.substring(0, prefixLength) + "#" + hash;
    }

    static String shortHash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 16);
        }
        catch (NoSuchAlgorithmException exception) {
            return Integer.toHexString(value.hashCode());
        }
    }

    record StepHandle(long id, boolean created) {
    }

    record StepState(String executionState, String domainStateDimension, String domainStateCode) {
    }

    record RunState(String executionState, String domainStateDimension, String domainStateCode) {
    }
}
