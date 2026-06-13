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
                        insert into official_verification_oss_run (
                            aggregate_run_id, package_id, operator_id, run_id, metric_code, state, score,
                            run_record_json, run_view_json, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, current_timestamp)
                        on conflict (run_id) do update set
                            aggregate_run_id = excluded.aggregate_run_id,
                            package_id = excluded.package_id,
                            operator_id = excluded.operator_id,
                            metric_code = excluded.metric_code,
                            state = excluded.state,
                            score = excluded.score,
                            run_record_json = excluded.run_record_json,
                            run_view_json = excluded.run_view_json,
                            created_at = current_timestamp
                        """,
                aggregateRunId,
                packageId,
                userId,
                record.runId(),
                record.metricCode(),
                record.state(),
                detailedView.score(),
                write(record),
                write(detailedView));
        super.saveDetailed(userId, record, detailedView);
    }

    @Override
    public List<OfficialVerificationRunRecord> list(String userId) {
        if (!StringUtils.hasText(userId)) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select run_record_json
                          from official_verification_oss_run
                         where operator_id = ?
                      order by created_at desc, metric_code asc
                        """,
                (rs, rowNum) -> readRecord(rs.getString("run_record_json")),
                userId.trim());
    }

    @Override
    public OfficialVerificationRunRecord find(String userId, String runId) {
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                            select run_record_json
                              from official_verification_oss_run
                             where run_id = ?
                            """,
                    (rs, rowNum) -> readRecord(rs.getString("run_record_json")),
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
                            select run_record_json
                              from official_verification_oss_run
                             where run_record_json like ?
                          order by created_at desc
                             limit 1
                            """,
                    (rs, rowNum) -> readRecord(rs.getString("run_record_json")),
                    "%\"requestId\":\"" + requestId.trim() + "\"%");
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
                            select run_view_json
                              from official_verification_oss_run
                             where operator_id = ?
                               and upper(metric_code) = upper(?)
                          order by created_at desc
                            """,
                    (rs, rowNum) -> readView(rs.getString("run_view_json")),
                    userId.trim(),
                    metricCode.trim());
        }
        return jdbcOperations.query("""
                        select run_view_json
                          from official_verification_oss_run
                         where operator_id = ?
                      order by created_at desc, metric_code asc
                        """,
                (rs, rowNum) -> readView(rs.getString("run_view_json")),
                userId.trim());
    }

    @Override
    public OfficialVerificationRunView findDetailed(String userId, String metricCode, String runId) {
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                            select run_view_json
                              from official_verification_oss_run
                             where run_id = ?
                            """,
                    (rs, rowNum) -> readView(rs.getString("run_view_json")),
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
                        select run_view_json
                          from official_verification_oss_run
                         where package_id = ?
                      order by created_at desc, metric_code asc
                        """,
                (rs, rowNum) -> readView(rs.getString("run_view_json")),
                packageId.trim());
    }

    private void ensureSchema() {
        jdbcOperations.execute("""
                create table if not exists official_verification_oss_run (
                    id bigserial primary key,
                    aggregate_run_id varchar(256) not null,
                    package_id varchar(256) not null,
                    operator_id varchar(160),
                    run_id varchar(256) not null,
                    metric_code varchar(32) not null,
                    state varchar(64),
                    score numeric(10, 2),
                    run_record_json text not null,
                    run_view_json text not null,
                    created_at timestamp(6) with time zone not null default current_timestamp,
                    constraint uq_official_verification_oss_run_run_id unique (run_id)
                )
                """);
        jdbcOperations.execute("""
                create index if not exists idx_oss_run_package_created
                    on official_verification_oss_run (package_id, created_at desc)
                """);
        jdbcOperations.execute("""
                create index if not exists idx_oss_run_operator_created
                    on official_verification_oss_run (operator_id, created_at desc)
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

    private OfficialVerificationRunRecord readRecord(String json) {
        try {
            return objectMapper.readValue(json, OfficialVerificationRunRecord.class);
        }
        catch (Exception exception) {
            throw new IllegalStateException("Failed to deserialize OSS official verification run record.", exception);
        }
    }

    private OfficialVerificationRunView readView(String json) throws SQLException {
        try {
            return objectMapper.readValue(json, SealedEvidenceOfficialRunView.class);
        }
        catch (Exception exception) {
            throw new SQLException("Failed to deserialize OSS official verification run view.", exception);
        }
    }
}
