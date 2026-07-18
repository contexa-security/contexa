package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCompletionRepository;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Objects;

public final class JdbcOfficialVerificationSnapshotCompletionRepository
        implements OfficialVerificationSnapshotCompletionRepository {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationSnapshotCompletionRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public boolean sealedEvidencePackageExists(String packageId, String tenantId) {
        return count("""
                select count(*) from sealed_evidence_package
                 where package_id = ? and tenant_id = ?
                """, packageId, tenantId) > 0;
    }

    @Override
    public boolean completeSnapshotExists(String aggregateRunId) {
        if (count("""
                select count(*) from official_verification_run_batch b
                join sealed_evidence_package sealed on sealed.package_id = b.package_id
                 where b.aggregate_run_id = ?
                """, aggregateRunId) <= 0) {
            return false;
        }
        Integer metricCount = nullableCount(
                "select count(*) from official_verification_metric_snapshot where aggregate_run_id = ?",
                aggregateRunId);
        Integer expectedMetricCount = nullableCount(
                "select max(expected_metric_count) from official_verification_run_batch where aggregate_run_id = ?",
                aggregateRunId);
        return matchingMetricCounts(metricCount, expectedMetricCount)
                && customerDisplayPayloadComplete(aggregateRunId)
                && countFindingWithoutProblem(aggregateRunId) == 0
                && countInputReadinessProblems(aggregateRunId) == 0
                && countStaleInputReadinessPurposeRows(aggregateRunId) == 0
                && countMissingPromptComparisons(aggregateRunId) == 0
                && actualProblemCountMatchesFindings(aggregateRunId)
                && countBlockedMetricsWithoutProblem(aggregateRunId) == 0;
    }

    @Override
    public boolean actualPromptProblemExists(String packageId, String aggregateRunId, String problemId) {
        return count("""
                select count(*) from official_actual_prompt_problem_ledger
                 where package_id = ? and aggregate_run_id = ? and problem_id = ?
                """, packageId, aggregateRunId, problemId) > 0;
    }

    private boolean matchingMetricCounts(Integer actual, Integer expected) {
        return actual != null && expected != null && expected > 0 && actual.intValue() == expected.intValue();
    }

    private boolean customerDisplayPayloadComplete(String aggregateRunId) {
        int expected = count("""
                select coalesce(sum(case when purpose_result = 'PURPOSE_FAILED' then 5 else 3 end), 0)
                  from official_metric_purpose_evaluation_ledger
                 where aggregate_run_id = ? and customer_visible = true
                """, aggregateRunId);
        int actual = count("""
                select count(*) from official_metric_customer_display_payload where aggregate_run_id = ?
                """, aggregateRunId);
        return expected == actual;
    }

    private int countFindingWithoutProblem(String aggregateRunId) {
        return count("""
                select count(*) from (
                    select check_code from official_verification_operator_finding
                     where aggregate_run_id = ? and check_code is not null and trim(check_code) <> ''
                    except
                    select problem_id from official_actual_prompt_problem_ledger where aggregate_run_id = ?
                ) missing_actual_prompt_problem
                """, aggregateRunId, aggregateRunId);
    }

    private int countInputReadinessProblems(String aggregateRunId) {
        return count("""
                select count(*) from official_actual_prompt_problem_ledger
                 where aggregate_run_id = ? and upper(coalesce(problem_type, '')) = 'INPUT_NOT_READY'
                """, aggregateRunId);
    }

    private int countStaleInputReadinessPurposeRows(String aggregateRunId) {
        return count("""
                select count(*) from official_metric_purpose_evaluation_ledger
                 where aggregate_run_id = ?
                   and upper(coalesce(purpose_result, '')) in ('NOT_EVALUATED_INPUT_NOT_READY', 'INPUT_NOT_READY')
                   and customer_visible = true
                """, aggregateRunId);
    }

    private int countMissingPromptComparisons(String aggregateRunId) {
        return count("""
                select count(*) from (
                    select distinct comparison_field_key from official_verification_operator_finding
                     where aggregate_run_id = ?
                       and comparison_field_key is not null and trim(comparison_field_key) <> ''
                    except
                    select distinct field_key from official_verification_prompt_comparison
                     where aggregate_run_id = ? and field_key is not null and trim(field_key) <> ''
                ) missing_prompt_comparison
                """, aggregateRunId, aggregateRunId);
    }

    private boolean actualProblemCountMatchesFindings(String aggregateRunId) {
        int problems = count("""
                select count(*) from official_actual_prompt_problem_ledger
                 where aggregate_run_id = ? and severity = 'BLOCKING'
                """, aggregateRunId);
        int findings = count("""
                select count(distinct check_code) from official_verification_operator_finding
                 where aggregate_run_id = ? and check_code is not null and trim(check_code) <> ''
                """, aggregateRunId);
        return problems == findings;
    }

    private int countBlockedMetricsWithoutProblem(String aggregateRunId) {
        return count("""
                select count(*) from official_verification_metric_snapshot m
                 where m.aggregate_run_id = ? and m.state = 'BLOCKED'
                   and upper(m.metric_code) not in ('MTR', 'RPI', 'PRE')
                   and not exists (
                       select 1 from official_verification_operator_finding f
                        where f.aggregate_run_id = m.aggregate_run_id and f.metric_code = m.metric_code
                   )
                """, aggregateRunId);
    }

    private int count(String sql, Object... arguments) {
        Integer value = nullableCount(sql, arguments);
        return value == null ? 0 : value;
    }

    private Integer nullableCount(String sql, Object... arguments) {
        return jdbcTemplate.queryForObject(sql, Integer.class, arguments);
    }
}