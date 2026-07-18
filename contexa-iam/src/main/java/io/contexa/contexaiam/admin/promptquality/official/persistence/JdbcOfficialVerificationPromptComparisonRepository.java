package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptComparisonRepository;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Objects;

public final class JdbcOfficialVerificationPromptComparisonRepository
        implements OfficialVerificationPromptComparisonRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationPromptComparisonRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }

    @Override
    public List<OfficialVerificationPromptComparison> findByPackageAndAggregateRunId(
            String packageId,
            String aggregateRunId) {
        return jdbcTemplate.query("""
                        select field_key, field_label, sealed_evidence_value, prompt_value,
                               official_fact_value, state, state_label, meaning,
                               related_metric_codes, related_check_codes, related_finding_ids,
                               related_issue_ids, related_remediation_group_ids, prompt_location,
                               evidence_source, recommended_owner, canonical_source
                          from official_verification_prompt_comparison
                         where package_id = ?
                           and aggregate_run_id = ?
                           and canonical_source <> 'OFFICIAL_FINDING'
                         order by case when state in (
                                      'PROMPT_MISSING', 'FACT_MISSING', 'VALUE_MISMATCH',
                                      'CONTRACT_MISMATCH', 'REQUIRED_MISSING',
                                      'CONDITIONAL_REQUIRED_MISSING', 'UNKNOWN_WITHOUT_REASON',
                                      'PROMPT_COMPACTED_SIGNAL', 'PRODUCER_NOT_AVAILABLE',
                                      'PROVISIONAL_EVIDENCE', 'NO_DIRECT_COMPARABLE',
                                      'BASELINE_MISMATCH_SIGNAL'
                                  ) then 0 else 1 end,
                                  field_label asc, field_key asc
                        """, rowMapper::promptComparison, packageId, aggregateRunId);
    }
}
