package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceOfficialRunView;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JdbcOfficialVerificationRunStore extends OfficialVerificationRunStore {

    private final JdbcOperations jdbcOperations;
    private final ObjectMapper objectMapper;

    public JdbcOfficialVerificationRunStore(JdbcOperations jdbcOperations, ObjectMapper objectMapper) {
        this.jdbcOperations = jdbcOperations;
        this.objectMapper = objectMapper;
        ensureSchema();
    }

    @Override
    public boolean ledgerBacked() {
        return true;
    }

    @Override
    public void saveDetailed(String userId, OfficialVerificationRunRecord record, OfficialVerificationRunView detailedView) {
        if (record == null || detailedView == null) {
            super.saveDetailed(userId, record, detailedView);
            return;
        }
        String packageId = evidence(record, "packageId");
        String aggregateRunId = aggregateRunId(detailedView);
        jdbcOperations.update("""
                        insert into verification_run_ledger (
                            run_id, user_id, metric_code, execution_path, state, state_tone,
                            requested_by, request_id, package_id, endpoint_key, endpoint_label,
                            round_number, score, passed_checks, total_checks, processing_time_ms,
                            message, evidence_references_json, checks_json, request_facts_json,
                            event_facts_json, prompt_facts_json, analysis_facts_json, events_json,
                            raw_evidence_json, requested_at, started_at, completed_at, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, current_timestamp)
                        on conflict (run_id) do update set
                            metric_code = excluded.metric_code,
                            execution_path = excluded.execution_path,
                            state = excluded.state,
                            state_tone = excluded.state_tone,
                            requested_by = excluded.requested_by,
                            request_id = excluded.request_id,
                            package_id = excluded.package_id,
                            endpoint_key = excluded.endpoint_key,
                            endpoint_label = excluded.endpoint_label,
                            round_number = excluded.round_number,
                            score = excluded.score,
                            passed_checks = excluded.passed_checks,
                            total_checks = excluded.total_checks,
                            processing_time_ms = excluded.processing_time_ms,
                            message = excluded.message,
                            evidence_references_json = excluded.evidence_references_json,
                            checks_json = excluded.checks_json,
                            request_facts_json = excluded.request_facts_json,
                            event_facts_json = excluded.event_facts_json,
                            prompt_facts_json = excluded.prompt_facts_json,
                            analysis_facts_json = excluded.analysis_facts_json,
                            events_json = excluded.events_json,
                            raw_evidence_json = excluded.raw_evidence_json,
                            requested_at = excluded.requested_at,
                            started_at = excluded.started_at,
                            completed_at = excluded.completed_at,
                            created_at = current_timestamp
                        """,
                record.runId(),
                userId,
                record.metricCode(),
                record.executionPath(),
                record.state(),
                detailedView.stateTone(),
                record.requestedBy(),
                evidence(record, "requestId"),
                packageId,
                detailedView.endpointKey(),
                detailedView.endpointLabel(),
                detailedView.round(),
                detailedView.score(),
                detailedView.passedChecks(),
                detailedView.totalChecks(),
                detailedView.processingTimeMs(),
                record.message(),
                write(record.evidenceReferences()),
                write(detailedView.checks()),
                write(detailedView.requestFacts()),
                write(detailedView.eventFacts()),
                write(detailedView.promptFacts()),
                write(detailedView.analysisFacts()),
                write(detailedView.events()),
                write(rawEvidenceWithAggregateRunId(detailedView, aggregateRunId)),
                timestamp(record.requestedAt()),
                timestamp(record.startedAt()),
                timestamp(record.completedAt()));
        super.saveDetailed(userId, record, detailedView);
    }

    @Override
    public List<OfficialVerificationRunRecord> list(String userId) {
        if (!StringUtils.hasText(userId)) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select *
                          from verification_run_ledger
                         where user_id = ?
                      order by requested_at desc nulls last, created_at desc, metric_code asc
                        """,
                (rs, rowNum) -> readRecord(rs),
                userId.trim());
    }

    @Override
    public OfficialVerificationRunRecord find(String userId, String runId) {
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                            select *
                              from verification_run_ledger
                             where run_id = ?
                            """,
                    (rs, rowNum) -> readRecord(rs),
                    runId.trim());
        }
        catch (EmptyResultDataAccessException ignored) {
            return null;
        }
    }

    @Override
    public OfficialVerificationRunRecord findByRequestId(String userId, String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                            select *
                              from verification_run_ledger
                             where request_id = ?
                          order by requested_at desc nulls last, created_at desc
                             limit 1
                            """,
                    (rs, rowNum) -> readRecord(rs),
                    requestId.trim());
        }
        catch (EmptyResultDataAccessException ignored) {
            return null;
        }
    }

    @Override
    public List<OfficialVerificationRunView> listDetailed(String userId, String metricCode) {
        if (!StringUtils.hasText(userId)) {
            return List.of();
        }
        if (StringUtils.hasText(metricCode)) {
            return jdbcOperations.query("""
                            select *
                              from verification_run_ledger
                             where user_id = ?
                               and upper(metric_code) = upper(?)
                          order by requested_at desc nulls last, created_at desc
                            """,
                    (rs, rowNum) -> readView(rs),
                    userId.trim(),
                    metricCode.trim());
        }
        return jdbcOperations.query("""
                        select *
                          from verification_run_ledger
                         where user_id = ?
                      order by requested_at desc nulls last, created_at desc, metric_code asc
                        """,
                (rs, rowNum) -> readView(rs),
                userId.trim());
    }

    @Override
    public OfficialVerificationRunView findDetailed(String userId, String metricCode, String runId) {
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                            select *
                              from verification_run_ledger
                             where run_id = ?
                            """,
                    (rs, rowNum) -> readView(rs),
                    runId.trim());
        }
        catch (EmptyResultDataAccessException ignored) {
            return null;
        }
    }

    @Override
    public OfficialVerificationRunView findDetailedByRunId(String runId) {
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                            select *
                              from verification_run_ledger
                             where run_id = ?
                            """,
                    (rs, rowNum) -> readView(rs),
                    runId.trim());
        }
        catch (EmptyResultDataAccessException ignored) {
            return null;
        }
    }

    @Override
    public List<OfficialVerificationRunView> listDetailedByPackageId(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select *
                          from verification_run_ledger
                         where package_id = ?
                      order by requested_at desc nulls last, created_at desc, metric_code asc
                        """,
                (rs, rowNum) -> readView(rs),
                packageId.trim());
    }

    private void ensureSchema() {
        jdbcOperations.execute("""
                create table if not exists verification_run_ledger (
                    id bigint generated by default as identity primary key,
                    run_id varchar(128) not null unique,
                    user_id varchar(160) not null,
                    metric_code varchar(32) not null,
                    execution_path varchar(160) not null,
                    state varchar(80),
                    state_tone varchar(80),
                    requested_by varchar(160),
                    request_id varchar(160),
                    package_id varchar(160),
                    endpoint_key varchar(80),
                    endpoint_label varchar(255),
                    round_number integer,
                    score double precision,
                    passed_checks integer,
                    total_checks integer,
                    processing_time_ms bigint,
                    message text,
                    evidence_references_json text,
                    checks_json text,
                    request_facts_json text,
                    event_facts_json text,
                    prompt_facts_json text,
                    analysis_facts_json text,
                    events_json text,
                    raw_evidence_json text,
                    requested_at timestamp,
                    started_at timestamp,
                    completed_at timestamp,
                    created_at timestamp default current_timestamp not null
                )
                """);
        jdbcOperations.execute("""
                create index if not exists idx_verification_run_ledger_user_requested_at
                    on verification_run_ledger (user_id, requested_at desc)
                """);
        jdbcOperations.execute("""
                create index if not exists idx_verification_run_ledger_user_metric
                    on verification_run_ledger (user_id, metric_code, requested_at desc)
                """);
        jdbcOperations.execute("""
                create index if not exists idx_verification_run_ledger_user_request
                    on verification_run_ledger (user_id, request_id)
                """);
        jdbcOperations.execute("""
                create index if not exists idx_verification_run_ledger_package_metric
                    on verification_run_ledger (package_id, metric_code, requested_at desc)
                """);
    }

    private String aggregateRunId(OfficialVerificationRunView detailedView) {
        Object raw = detailedView.rawEvidence() == null ? null : detailedView.rawEvidence().get("aggregateRunId");
        if (raw != null && StringUtils.hasText(String.valueOf(raw))) {
            return String.valueOf(raw).trim();
        }
        String runId = detailedView.runId();
        String metric = detailedView.endpointKey();
        if (StringUtils.hasText(runId) && StringUtils.hasText(metric)) {
            String suffix = "-" + metric.trim().toLowerCase();
            if (runId.toLowerCase().endsWith(suffix)) {
                return runId.substring(0, runId.length() - suffix.length());
            }
        }
        return StringUtils.hasText(runId) ? runId : "oss-run-" + Instant.now().toEpochMilli();
    }

    private String evidence(OfficialVerificationRunRecord record, String key) {
        Map<String, String> references = record.evidenceReferences();
        String value = references == null ? null : references.get(key);
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private String write(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("Failed to serialize OSS official verification run.", exception);
        }
    }

    private OfficialVerificationRunRecord readRecord(ResultSet rs) throws SQLException {
        return new OfficialVerificationRunRecord(
                rs.getString("run_id"),
                rs.getString("metric_code"),
                rs.getString("execution_path"),
                rs.getString("state"),
                rs.getString("requested_by"),
                instant(rs, "requested_at"),
                instant(rs, "started_at"),
                instant(rs, "completed_at"),
                rs.getString("message"),
                readStringMap(rs.getString("evidence_references_json")));
    }

    private OfficialVerificationRunView readView(ResultSet rs) throws SQLException {
        try {
            return new SealedEvidenceOfficialRunView(
                    rs.getString("run_id"),
                    intValue(rs, "round_number"),
                    rs.getString("endpoint_key"),
                    rs.getString("endpoint_label"),
                    rs.getString("request_id"),
                    doubleValue(rs, "score"),
                    intValue(rs, "passed_checks"),
                    intValue(rs, "total_checks"),
                    longValue(rs, "processing_time_ms"),
                    rs.getString("state"),
                    rs.getString("state_tone"),
                    rs.getString("message"),
                    textTime(rs, "started_at"),
                    textTime(rs, "completed_at"),
                    readList(rs.getString("checks_json"), SealedEvidenceOfficialRunView.SealedEvidenceCheckView.class),
                    readStringMap(rs.getString("request_facts_json")),
                    readStringMap(rs.getString("event_facts_json")),
                    readStringMap(rs.getString("prompt_facts_json")),
                    readStringMap(rs.getString("analysis_facts_json")),
                    readList(rs.getString("events_json"), SealedEvidenceOfficialRunView.SealedEvidenceEventView.class),
                    readObjectMap(rs.getString("raw_evidence_json")));
        }
        catch (Exception exception) {
            throw new SQLException("Failed to deserialize OSS official verification run view.", exception);
        }
    }

    private Map<String, Object> rawEvidenceWithAggregateRunId(OfficialVerificationRunView view, String aggregateRunId) {
        Map<String, Object> raw = new LinkedHashMap<>();
        if (view.rawEvidence() != null) {
            raw.putAll(view.rawEvidence());
        }
        raw.putIfAbsent("aggregateRunId", aggregateRunId);
        return raw;
    }

    private Timestamp timestamp(Instant value) {
        return value == null ? null : Timestamp.from(value);
    }

    private Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private String textTime(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? "" : value.toInstant().toString();
    }

    private int intValue(ResultSet rs, String column) throws SQLException {
        int value = rs.getInt(column);
        return rs.wasNull() ? 0 : value;
    }

    private double doubleValue(ResultSet rs, String column) throws SQLException {
        double value = rs.getDouble(column);
        return rs.wasNull() ? 0.0d : value;
    }

    private Long longValue(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private Map<String, String> readStringMap(String json) {
        try {
            if (!StringUtils.hasText(json)) {
                return Map.of();
            }
            return objectMapper.readValue(
                    json,
                    objectMapper.getTypeFactory().constructMapType(Map.class, String.class, String.class));
        }
        catch (Exception exception) {
            throw new IllegalStateException("Failed to deserialize official verification string map.", exception);
        }
    }

    private Map<String, Object> readObjectMap(String json) {
        try {
            if (!StringUtils.hasText(json)) {
                return Map.of();
            }
            return objectMapper.readValue(
                    json,
                    objectMapper.getTypeFactory().constructMapType(Map.class, String.class, Object.class));
        }
        catch (Exception exception) {
            throw new IllegalStateException("Failed to deserialize official verification object map.", exception);
        }
    }

    private <T> List<T> readList(String json, Class<T> itemType) {
        try {
            if (!StringUtils.hasText(json)) {
                return List.of();
            }
            return objectMapper.readValue(
                    json,
                    objectMapper.getTypeFactory().constructCollectionType(List.class, itemType));
        }
        catch (Exception exception) {
            throw new IllegalStateException("Failed to deserialize official verification list.", exception);
        }
    }
}
