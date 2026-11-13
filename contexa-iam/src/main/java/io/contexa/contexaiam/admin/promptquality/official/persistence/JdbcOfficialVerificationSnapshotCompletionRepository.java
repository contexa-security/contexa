package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCompletionRepository;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Arrays;
import java.util.Objects;

public final class JdbcOfficialVerificationSnapshotCompletionRepository
        implements OfficialVerificationSnapshotCompletionRepository {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationSnapshotCompletionRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    /** A package stored without a tenant belongs to the deployment default tenant, as it does when it is verified. */
    @Override
    public boolean sealedEvidencePackageExists(String packageId, String tenantId) {
        return count("""
                select count(*) from ctxa_sealed_evidence_package
                 where package_id = ? and coalesce(nullif(tenant_id, ''), ?) = ?
                """, packageId, SealedEvidencePackage.DEFAULT_TENANT_ID, tenantId) > 0;
    }

    @Override
    public boolean completeSnapshotExists(String aggregateRunId) {
        return completion(aggregateRunId).complete();
    }

    /** Complete, and its execution ended: COMPLETED at 100 percent, without a failure. */
    @Override
    public boolean publishableSnapshotExists(String aggregateRunId) {
        Completion completion = completion(aggregateRunId);
        return completion.complete() && completion.completedExecutions() > 0;
    }

    @Override
    public boolean executionRecordExists(String aggregateRunId) {
        return count("""
                select count(*) from ctxa_official_verification_execution_lock
                 where aggregate_run_id = ?
                """, aggregateRunId) > 0;
    }

    @Override
    public boolean actualPromptProblemExists(String packageId, String aggregateRunId, String problemId) {
        return count("""
                select count(*) from ctxa_official_actual_prompt_problem_ledger
                 where package_id = ? and aggregate_run_id = ? and problem_id = ?
                """, packageId, aggregateRunId, problemId) > 0;
    }

    /**
     * The counts the completion of a run stands on, read with one statement: the detail of a run reads them on its
     * first request, within PromptQualityQueryBudgets.OFFICIAL_VERIFICATION_DETAIL_INITIAL.
     */
    private Completion completion(String aggregateRunId) {
        Object[] arguments = new Object[COMPLETION_ARGUMENTS];
        Arrays.fill(arguments, aggregateRunId);
        Completion completion = jdbcTemplate.queryForObject(COMPLETION_SQL, (rs, rowNumber) -> new Completion(
                rs.getInt("batches_with_package"),
                rs.getInt("metric_count"),
                (Integer) rs.getObject("expected_metric_count", Integer.class),
                rs.getInt("purpose_actual"),
                rs.getInt("purpose_expected"),
                rs.getInt("display_expected"),
                rs.getInt("display_actual"),
                rs.getInt("findings_without_problem"),
                rs.getInt("input_readiness_problems"),
                rs.getInt("input_readiness_display_payloads"),
                rs.getInt("missing_prompt_comparisons"),
                rs.getInt("blocking_problems"),
                rs.getInt("finding_checks"),
                rs.getInt("blocked_metrics_without_problem"),
                rs.getInt("completed_executions")), arguments);
        // a statement without a row (none on PostgreSQL) says nothing is complete
        return completion == null ? Completion.NONE : completion;
    }

    private static final int COMPLETION_ARGUMENTS = 17;

    private static final String COMPLETION_SQL = """
            select
              (select count(*) from ctxa_official_verification_run_batch b
                 join ctxa_sealed_evidence_package sealed on sealed.package_id = b.package_id
                where b.aggregate_run_id = ?) as batches_with_package,
              (select count(*) from ctxa_official_verification_metric_snapshot where aggregate_run_id = ?) as metric_count,
              (select max(expected_metric_count) from ctxa_official_verification_run_batch
                where aggregate_run_id = ?) as expected_metric_count,
              (select count(*)
                 from ctxa_official_metric_purpose_evaluation_ledger purpose
                 join ctxa_official_metric_evaluation_contract evaluation
                   on evaluation.contract_version = purpose.contract_version
                  and upper(evaluation.metric_code) = upper(purpose.metric_code)
                  and upper(evaluation.check_code) = upper(purpose.check_code)
                 join ctxa_official_metric_purpose_contract metric
                   on metric.contract_version = evaluation.contract_version
                  and upper(metric.metric_code) = upper(evaluation.metric_code)
                 join ctxa_official_metric_contract_version version
                   on version.contract_version = evaluation.contract_version
                  and version.active = true
                where purpose.aggregate_run_id = ?
                  and upper(coalesce(metric.metric_role, '')) <> 'LLM_DECISION_QUALITY') as purpose_actual,
              (select count(*)
                 from ctxa_official_metric_evaluation_contract contract
                 join ctxa_official_metric_purpose_contract metric
                   on metric.contract_version = contract.contract_version
                  and upper(metric.metric_code) = upper(contract.metric_code)
                 join ctxa_official_metric_contract_version version
                   on version.contract_version = contract.contract_version
                  and version.active = true
                where upper(coalesce(metric.metric_role, '')) <> 'LLM_DECISION_QUALITY'
                  and exists (
                      select 1 from ctxa_official_verification_metric_snapshot snapshot
                       where snapshot.aggregate_run_id = ?
                         and upper(snapshot.metric_code) = upper(contract.metric_code)
                  )) as purpose_expected,
              (select coalesce(sum(case when purpose_result = 'PURPOSE_FAILED' then 5 else 3 end), 0)
                 from ctxa_official_metric_purpose_evaluation_ledger
                where aggregate_run_id = ?
                  and customer_visible = true
                  and purpose_result <> 'INPUT_NOT_READY') as display_expected,
              (select count(*) from ctxa_official_metric_customer_display_payload
                where aggregate_run_id = ?) as display_actual,
              (select count(*) from (
                   select check_code from ctxa_official_verification_operator_finding
                    where aggregate_run_id = ? and check_code is not null and trim(check_code) <> ''
                   except
                   select problem_id from ctxa_official_actual_prompt_problem_ledger where aggregate_run_id = ?
               ) missing_actual_prompt_problem) as findings_without_problem,
              (select count(*) from ctxa_official_actual_prompt_problem_ledger
                where aggregate_run_id = ? and upper(coalesce(problem_type, '')) = 'INPUT_NOT_READY')
                as input_readiness_problems,
              (select count(*) from ctxa_official_metric_purpose_evaluation_ledger purpose
                where purpose.aggregate_run_id = ?
                  and upper(coalesce(purpose.purpose_result, ''))
                      in ('NOT_EVALUATED_INPUT_NOT_READY', 'INPUT_NOT_READY')
                  and exists (
                      select 1 from ctxa_official_metric_customer_display_payload payload
                       where payload.aggregate_run_id = purpose.aggregate_run_id
                         and upper(payload.metric_code) = upper(purpose.metric_code)
                         and payload.check_code = purpose.check_code
                  )) as input_readiness_display_payloads,
              (select count(*) from (
                   select distinct comparison_field_key from ctxa_official_verification_operator_finding
                    where aggregate_run_id = ?
                      and comparison_field_key is not null and trim(comparison_field_key) <> ''
                   except
                   select distinct field_key from ctxa_official_verification_prompt_comparison
                    where aggregate_run_id = ? and field_key is not null and trim(field_key) <> ''
               ) missing_prompt_comparison) as missing_prompt_comparisons,
              (select count(*) from ctxa_official_actual_prompt_problem_ledger
                where aggregate_run_id = ? and severity = 'BLOCKING') as blocking_problems,
              (select count(distinct check_code) from ctxa_official_verification_operator_finding
                where aggregate_run_id = ? and check_code is not null and trim(check_code) <> '') as finding_checks,
              (select count(*) from ctxa_official_verification_metric_snapshot m
                where m.aggregate_run_id = ? and m.state = 'BLOCKED'
                  and upper(m.metric_code) not in ('MTR', 'RPI', 'PRE')
                  and not exists (
                      select 1 from ctxa_official_verification_operator_finding f
                       where f.aggregate_run_id = m.aggregate_run_id and f.metric_code = m.metric_code
                  )) as blocked_metrics_without_problem,
              (select count(*) from ctxa_official_verification_execution_lock
                where aggregate_run_id = ?
                  and state = 'COMPLETED'
                  and progress_percent = 100
                  and failure_stage is null
                  and failure_reason is null) as completed_executions
            """;

    /** The counts of {@link #COMPLETION_SQL}, and what makes a run complete. */
    private record Completion(int batchesWithPackage, int metricCount, Integer expectedMetricCount,
                              int purposeActual, int purposeExpected, int displayExpected, int displayActual,
                              int findingsWithoutProblem, int inputReadinessProblems,
                              int inputReadinessDisplayPayloads, int missingPromptComparisons,
                              int blockingProblems, int findingChecks, int blockedMetricsWithoutProblem,
                              int completedExecutions) {

        static final Completion NONE = new Completion(0, 0, null, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        boolean complete() {
            return batchesWithPackage > 0
                    && expectedMetricCount != null && expectedMetricCount > 0 && metricCount == expectedMetricCount
                    && purposeExpected > 0 && purposeActual == purposeExpected
                    && displayExpected == displayActual
                    && findingsWithoutProblem == 0
                    && inputReadinessProblems == 0
                    && inputReadinessDisplayPayloads == 0
                    && missingPromptComparisons == 0
                    && blockingProblems == findingChecks
                    && blockedMetricsWithoutProblem == 0;
        }
    }

    private int count(String sql, Object... arguments) {
        Integer value = nullableCount(sql, arguments);
        return value == null ? 0 : value;
    }

    private Integer nullableCount(String sql, Object... arguments) {
        return jdbcTemplate.queryForObject(sql, Integer.class, arguments);
    }
}
