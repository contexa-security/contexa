package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptFieldStateWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationPromptFieldStateWriter
        implements OfficialVerificationPromptFieldStateWriter {

    private static final String INSERT_SQL = """
            insert into official_prompt_field_state_ledger (
                package_id, aggregate_run_id, official_run_id, field_key,
                source_type, source_field_path, source_class, field_state,
                value_type, value_hash, value_length, value_preview,
                required_policy, applicability_rule, applicability_evidence,
                projection_policy, prompt_presence_state, sealed_evidence_presence_state,
                producer_status, absence_reason_code, absence_reason_text,
                metric_impact_policy, blocking_policy, blocking_candidate,
                quality_relevance, raw_blocking_candidate, official_blocking_candidate,
                created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
    private static final String INSERT_MISSING_SQL = """
            insert into official_prompt_field_state_ledger (
                package_id, aggregate_run_id, official_run_id, field_key,
                source_type, source_field_path, source_class, field_state,
                value_type, value_hash, value_length, value_preview,
                required_policy, applicability_rule, applicability_evidence,
                projection_policy, prompt_presence_state, sealed_evidence_presence_state,
                producer_status, absence_reason_code, absence_reason_text,
                metric_impact_policy, blocking_policy, blocking_candidate,
                quality_relevance, raw_blocking_candidate, official_blocking_candidate, created_at
            )
            select ?, ?, null, d.field_key,
                   left(coalesce(nullif(d.source_model, ''), 'OFFICIAL_FIELD_DEFINITION'), 128),
                   d.source_field_path, d.source_class, 'PRODUCER_NOT_AVAILABLE', d.value_type,
                   null, null, null, d.required_policy, d.applicability_rule,
                   coalesce(nullif(d.not_applicable_rule, ''), 'Runtime manifest did not emit this active field.'),
                   d.projection_policy, 'NOT_RECORDED_IN_RUNTIME_MANIFEST', 'NOT_RECORDED_IN_RUNTIME_MANIFEST',
                   'NOT_RECORDED_IN_RUNTIME_MANIFEST', 'FIELD_STATE_NOT_EMITTED',
                   'Active field definition existed but the sealed runtime manifest did not emit a state row.',
                   left(coalesce(nullif(d.metric_codes, ''), 'AUDIT_ONLY'), 128),
                   'NON_BLOCKING_FIELD_COVERAGE_GAP', false, d.quality_relevance, false, false, ?
              from official_prompt_field_definition d
             where d.is_active = true
               and not exists (
                   select 1 from official_prompt_field_state_ledger s
                    where s.aggregate_run_id = ? and s.field_key = d.field_key
               )
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationPromptFieldStateWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(Command command) {
        jdbcTemplate.update(INSERT_SQL,
                command.packageId(), command.aggregateRunId(), null, command.fieldKey(), command.sourceType(),
                command.sourceFieldPath(), command.sourceClass(), command.fieldState(), command.valueType(),
                command.valueHash(), command.valueLength(), command.valuePreview(), command.requiredPolicy(),
                command.applicabilityRule(), command.applicabilityEvidence(), command.projectionPolicy(),
                command.promptPresenceState(), command.sealedEvidencePresenceState(), command.producerStatus(),
                command.absenceReasonCode(), command.absenceReasonText(), command.metricImpactPolicy(),
                command.blockingPolicy(), command.blockingCandidate(), command.qualityRelevance(),
                command.rawBlockingCandidate(), command.officialBlockingCandidate(), Timestamp.from(Instant.now()));
    }

    @Override
    public void insertMissingActiveDefinitions(String packageId, String aggregateRunId) {
        jdbcTemplate.update(
                INSERT_MISSING_SQL, packageId, aggregateRunId, Timestamp.from(Instant.now()), aggregateRunId);
    }
}
