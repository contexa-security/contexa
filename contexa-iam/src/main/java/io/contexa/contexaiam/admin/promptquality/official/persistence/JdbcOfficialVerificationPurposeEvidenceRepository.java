package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPurposeEvidenceRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public final class JdbcOfficialVerificationPurposeEvidenceRepository implements OfficialVerificationPurposeEvidenceRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationPurposeEvidenceRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }
    @Override
    public List<OperatorPurposeEvidence> findByAggregateRunId(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return List.of();
        }
        List<OperatorPurposeEvidence> rows = jdbcTemplate.query("""
                        select aggregate_run_id, package_id, metric_code, check_code,
                               contract_version, signal_key, prompt_location, evidence_value,
                               evidence_hash, interpretation, purpose_result, customer_visible,
                               readiness_scope, created_at,
                               coalesce(evidence.runtime_facts_json, '[]') as runtime_facts_json,
                               coalesce(nullif(evidence.context_items_json, '[]'), (
                                   select payload.context_items_json
                                     from official_metric_customer_display_payload payload
                                    where payload.aggregate_run_id = evidence.aggregate_run_id
                                      and upper(payload.metric_code) = upper(evidence.metric_code)
                                      and payload.check_code = evidence.check_code
                                      and payload.contract_version = evidence.contract_version
                                      and payload.display_role = case
                                              when evidence.purpose_result = 'PURPOSE_FAILED' then 'FAIL_EVIDENCE'
                                              else 'PASS_EVIDENCE'
                                          end
                                      and coalesce(payload.context_items_json, '[]') <> '[]'
                                    order by payload.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_metric_purpose_evidence_ledger evidence
                         where aggregate_run_id = ?
                         order by metric_code asc, check_code asc, evidence.id asc
                        """,
                rowMapper::purposeEvidenceRow,
                aggregateRunId);
        return rows == null ? List.of() : rows;
    }

    @Override
    public List<OperatorPurposeEvidence> findByAggregateRunIds(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select aggregate_run_id, package_id, metric_code, check_code,
                               contract_version, signal_key, prompt_location, evidence_value,
                               evidence_hash, interpretation, purpose_result, customer_visible,
                               readiness_scope, created_at,
                               coalesce(evidence.runtime_facts_json, '[]') as runtime_facts_json,
                               coalesce(nullif(evidence.context_items_json, '[]'), (
                                   select payload.context_items_json
                                     from official_metric_customer_display_payload payload
                                    where payload.aggregate_run_id = evidence.aggregate_run_id
                                      and upper(payload.metric_code) = upper(evidence.metric_code)
                                      and payload.check_code = evidence.check_code
                                      and payload.contract_version = evidence.contract_version
                                      and payload.display_role = case
                                              when evidence.purpose_result = 'PURPOSE_FAILED' then 'FAIL_EVIDENCE'
                                              else 'PASS_EVIDENCE'
                                          end
                                      and coalesce(payload.context_items_json, '[]') <> '[]'
                                    order by payload.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_metric_purpose_evidence_ledger evidence
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, metric_code asc, check_code asc, evidence.id asc
                        """.formatted(placeholders(aggregateRunIds)),
                rowMapper::purposeEvidenceRow,
                aggregateRunIds.toArray());
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }
}