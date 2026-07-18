package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotRelationIntegrityRepository;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Objects;

public final class JdbcOfficialVerificationSnapshotRelationIntegrityRepository
        implements OfficialVerificationSnapshotRelationIntegrityRepository {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationSnapshotRelationIntegrityRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }
    @Override
    public void assertMetricSnapshotComplete(String aggregateRunId) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from official_verification_metric_snapshot where aggregate_run_id = ?",
                Integer.class,
                aggregateRunId);
        Integer expectedMetricCount = jdbcTemplate.queryForObject(
                "select max(expected_metric_count) from official_verification_run_batch where aggregate_run_id = ?",
                Integer.class,
                aggregateRunId);
        if (count == null || expectedMetricCount == null || expectedMetricCount <= 0
                || count.intValue() != expectedMetricCount.intValue()) {
            throw new IllegalStateException("Official verification metric snapshot count does not match expected metric count. aggregateRunId="
                    + aggregateRunId + ", expected=" + expectedMetricCount + ", actual=" + count);
        }
    }

    @Override
    public void assertPromptComparisonLinksComplete(String aggregateRunId) {
        Integer missing = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select distinct comparison_field_key
                                  from official_verification_operator_finding
                                 where aggregate_run_id = ?
                                   and comparison_field_key is not null
                                   and trim(comparison_field_key) <> ''
                                except
                                select distinct field_key
                                  from official_verification_prompt_comparison
                                 where aggregate_run_id = ?
                                   and field_key is not null
                                   and trim(field_key) <> ''
                               ) missing_prompt_comparison
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (missing != null && missing > 0) {
            throw new IllegalStateException("Operator finding comparison fields are missing prompt comparison linkage. aggregateRunId="
                    + aggregateRunId + ", missingFieldCount=" + missing);
        }
    }

    @Override
    public void assertActualPromptProblemLedgerAligned(String aggregateRunId) {
        Integer actualProblemCount = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and severity = 'BLOCKING'
                        """,
                Integer.class,
                aggregateRunId);
        Integer findingCount = jdbcTemplate.queryForObject("""
                        select count(distinct check_code)
                           from official_verification_operator_finding
                          where aggregate_run_id = ?
                            and check_code is not null
                            and trim(check_code) <> ''
                         """,
                Integer.class,
                aggregateRunId);
        if ((findingCount == null ? 0 : findingCount) != (actualProblemCount == null ? 0 : actualProblemCount)) {
            throw new IllegalStateException("Actual prompt problem ledger is not aligned with operator findings. aggregateRunId="
                    + aggregateRunId + ", distinctMetricProblemIds=" + findingCount
                    + ", actualPromptProblems=" + actualProblemCount);
        }
        Integer blockedMetricWithoutProblem = jdbcTemplate.queryForObject("""
                        /* blocked_metric_without_problem */
                        select count(*)
                          from official_verification_metric_snapshot m
                         where m.aggregate_run_id = ?
                           and m.state = 'BLOCKED'
                           and upper(m.metric_code) not in ('MTR', 'RPI', 'PRE')
                           and not exists (
                                select 1
                                  from official_verification_operator_finding f
                                 where f.aggregate_run_id = m.aggregate_run_id
                                   and f.metric_code = m.metric_code
                           )
                        """,
                Integer.class,
                aggregateRunId);
        if (blockedMetricWithoutProblem != null && blockedMetricWithoutProblem > 0) {
            throw new IllegalStateException("Blocked metric snapshot is missing actual prompt problem linkage. aggregateRunId="
                    + aggregateRunId + ", blockedMetricWithoutProblem=" + blockedMetricWithoutProblem);
        }
    }

    @Override
    public void assertPromptFieldDefinitionsCoverStateLedger(String aggregateRunId) {
        Integer undefinedStateRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select distinct field_key
                                  from official_prompt_field_state_ledger
                                 where aggregate_run_id = ?
                                   and field_key is not null
                                   and trim(field_key) <> ''
                                except
                                select distinct field_key
                                  from official_prompt_field_definition
                                 where is_active = true
                                ) missing_field_definitions
                        """,
                Integer.class,
                aggregateRunId);
        if (undefinedStateRows != null && undefinedStateRows > 0) {
            throw new IllegalStateException("Prompt field state ledger contains fields that are not registered in official_prompt_field_definition. aggregateRunId="
                    + aggregateRunId + ", missingDefinitionCount=" + undefinedStateRows);
        }
        Integer missingStateRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_prompt_field_definition d
                         where d.is_active = true
                           and not exists (
                                select 1
                                  from official_prompt_field_state_ledger s
                                 where s.aggregate_run_id = ?
                                   and s.field_key = d.field_key
                           )
                        """,
                Integer.class,
                aggregateRunId);
        if (missingStateRows != null && missingStateRows > 0) {
            throw new IllegalStateException("Prompt field definition is missing runtime state ledger rows. aggregateRunId="
                    + aggregateRunId + ", missingStateCount=" + missingStateRows);
        }
    }

}
