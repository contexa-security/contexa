package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCustomerPurposeIntegrityRepository;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Objects;

public final class JdbcOfficialVerificationCustomerPurposeIntegrityRepository
        implements OfficialVerificationCustomerPurposeIntegrityRepository {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationCustomerPurposeIntegrityRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }
    @Override
    public void assertClean(String aggregateRunId) {
        Integer invalidCustomerVisiblePurposeState = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_state_contract */
                        select count(*)
                          from (
                                select purpose_result
                                  from official_metric_purpose_evaluation_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                union all
                                select purpose_result
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                               ) purpose_rows
                         where upper(coalesce(purpose_result, '')) not in (
                               'INPUT_NOT_READY',
                               'NOT_APPLICABLE',
                               'PURPOSE_PASSED',
                               'PURPOSE_FAILED'
                         )
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (invalidCustomerVisiblePurposeState != null && invalidCustomerVisiblePurposeState > 0) {
            throw new IllegalStateException("Customer-visible purpose ledgers contain non-contract purpose_result. aggregateRunId="
                    + aggregateRunId + ", invalidStateCount=" + invalidCustomerVisiblePurposeState
                    + ", firstOffender=" + firstCustomerVisiblePurposeStateOffender(aggregateRunId));
        }
        Integer purposeActualTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_actual_technical_text */
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                          where aggregate_run_id = ?
                            and customer_visible = true
                            and (
                                  actual_value ilike '%Evidence:%'
                                  or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                  or actual_value like '확인된 값:%'
                                  or actual_value like '%실제 프롬프트에서 확인된 값은'
                                  or actual_value like '%확인된 근거:%'
                                  or actual_value like '%검사 대상 항목%'
                                  or actual_value like '% 생략됨'
                            )
                        """,
                Integer.class,
                aggregateRunId);
        Integer purposeNextActionTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_next_action_technical_text */
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                           and (
                                 next_action ilike '%Evidence:%'
                                 or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                 or next_action like '조치:%'
                                 or next_action like '%누락된 항목%'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer purposeReverifyTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_reverify_technical_text */
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                           and (
                                 reverify_criterion ilike '%Evidence:%'
                                 or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                 or reverify_criterion like '재검증 기준:%'
                                 or reverify_criterion like '%누락된 항목%'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer purposeEvidenceTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_evidence_technical_text */
                        select count(*)
                          from official_metric_purpose_evidence_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                           and (
                                 evidence_value ilike '%Evidence:%'
                                 or evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer actualPromptProblemTechnicalText = jdbcTemplate.queryForObject("""
                        /* actual_prompt_problem_customer_technical_text */
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and (
                                prompt_value ilike '%Evidence:%'
                                or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or expected_state ilike '%Evidence:%'
                                or expected_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or expected_state like '문제:%'
                                or actual_state ilike '%Evidence:%'
                                or actual_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or actual_state like '확인된 값:%'
                                or fix_action ilike '%Evidence:%'
                                or fix_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or reverify_criterion_detail ilike '%Evidence:%'
                                or reverify_criterion_detail ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer promptQualityIssueTechnicalText = jdbcTemplate.queryForObject("""
                        /* prompt_quality_issue_customer_technical_text */
                        select count(*)
                          from prompt_quality_issue
                         where aggregate_run_id = ?
                           and (
                                actual_value ilike '%Evidence:%'
                                or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or next_action ilike '%Evidence:%'
                                or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or reverify_criterion ilike '%Evidence:%'
                                or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer promptComparisonTechnicalText = jdbcTemplate.queryForObject("""
                        /* prompt_comparison_customer_technical_text */
                        select count(*)
                          from official_verification_prompt_comparison
                         where aggregate_run_id = ?
                            and (
                                 prompt_value ilike '%Evidence:%'
                                 or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or prompt_value like '확인된 값:%'
                                 or official_fact_value ilike '%Evidence:%'
                                 or official_fact_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or official_fact_value like '문제:%'
                                 or sealed_evidence_value ilike '%Evidence:%'
                                 or sealed_evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                            )
                        """,
                Integer.class,
                aggregateRunId);
        int actualCount = purposeActualTechnicalText == null ? 0 : purposeActualTechnicalText;
        int nextActionCount = purposeNextActionTechnicalText == null ? 0 : purposeNextActionTechnicalText;
        int reverifyCount = purposeReverifyTechnicalText == null ? 0 : purposeReverifyTechnicalText;
        int evidenceCount = purposeEvidenceTechnicalText == null ? 0 : purposeEvidenceTechnicalText;
        int actualProblemCount = actualPromptProblemTechnicalText == null ? 0 : actualPromptProblemTechnicalText;
        int issueCount = promptQualityIssueTechnicalText == null ? 0 : promptQualityIssueTechnicalText;
        int comparisonCount = promptComparisonTechnicalText == null ? 0 : promptComparisonTechnicalText;
        if (actualCount > 0 || nextActionCount > 0 || reverifyCount > 0
                || evidenceCount > 0 || actualProblemCount > 0 || issueCount > 0 || comparisonCount > 0) {
            String firstOffender = firstCustomerVisiblePurposeLedgerTechnicalLocation(aggregateRunId);
            throw new IllegalStateException("Customer-visible purpose ledgers contain raw technical evidence. aggregateRunId="
                    + aggregateRunId + ", actualValueCount=" + actualCount + ", nextActionCount=" + nextActionCount
                    + ", reverifyCriterionCount=" + reverifyCount + ", evidenceValueCount=" + evidenceCount
                    + ", actualPromptProblemCount=" + actualProblemCount
                    + ", promptQualityIssueCount=" + issueCount + ", promptComparisonCount=" + comparisonCount
                    + ", firstOffender=" + firstOffender);
        }
        Integer duplicatedPurposeEvidenceText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_evidence_duplicate_text */
                        select count(*)
                          from (
                                select metric_code,
                                       lower(regexp_replace(trim(evidence_value), '[.!?]+$', '')) as evidence_key,
                                       count(*) as duplicate_count
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(evidence_value), '') <> ''
                                 group by metric_code, lower(regexp_replace(trim(evidence_value), '[.!?]+$', ''))
                                having count(*) > 1
                               ) duplicated
                        """,
                Integer.class,
                aggregateRunId);
        if (duplicatedPurposeEvidenceText != null && duplicatedPurposeEvidenceText > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence repeats across checks. aggregateRunId="
                    + aggregateRunId + ", duplicateGroupCount=" + duplicatedPurposeEvidenceText
                    + ", firstOffender=" + firstCustomerVisiblePurposeEvidenceDuplicate(aggregateRunId));
        }
        Integer duplicatedRuntimeFacts = jdbcTemplate.queryForObject("""
                        /* customer_visible_runtime_fact_duplicate_text */
                        select count(*)
                          from (
                                select metric_code,
                                       lower(trim(fact)) as fact_key,
                                       count(distinct check_code) as duplicate_count
                                  from official_metric_purpose_evidence_ledger,
                                       jsonb_array_elements_text(runtime_facts_json::jsonb) as fact
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(fact), '') <> ''
                                 group by metric_code, lower(trim(fact))
                                having count(distinct check_code) > 1
                               ) duplicated
                        """,
                Integer.class,
                aggregateRunId);
        if (duplicatedRuntimeFacts != null && duplicatedRuntimeFacts > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible runtime facts repeat across checks. aggregateRunId="
                    + aggregateRunId + ", duplicateGroupCount=" + duplicatedRuntimeFacts
                    + ", firstOffender=" + firstCustomerVisibleRuntimeFactDuplicate(aggregateRunId));
        }
    }

    private String firstCustomerVisiblePurposeEvidenceDuplicate(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select metric_code || ':' || string_agg(check_code, ', ' order by check_code) as offender
                          from (
                                select metric_code,
                                       check_code,
                                       lower(regexp_replace(trim(evidence_value), '[.!?]+$', '')) as evidence_key
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(evidence_value), '') <> ''
                               ) evidence
                         where (metric_code, evidence_key) in (
                               select metric_code,
                                      lower(regexp_replace(trim(evidence_value), '[.!?]+$', '')) as evidence_key
                                 from official_metric_purpose_evidence_ledger
                                where aggregate_run_id = ?
                                  and customer_visible = true
                                  and coalesce(trim(evidence_value), '') <> ''
                                group by metric_code, lower(regexp_replace(trim(evidence_value), '[.!?]+$', ''))
                               having count(*) > 1
                         )
                         group by metric_code, evidence_key
                         order by metric_code, evidence_key
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId);
        return rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String firstCustomerVisibleRuntimeFactDuplicate(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select metric_code || ':' || string_agg(check_code, ', ' order by check_code) || ':' || fact_key as offender
                          from (
                                select metric_code,
                                       check_code,
                                       lower(trim(fact)) as fact_key
                                  from official_metric_purpose_evidence_ledger,
                                       jsonb_array_elements_text(runtime_facts_json::jsonb) as fact
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(fact), '') <> ''
                               ) evidence
                         where (metric_code, fact_key) in (
                               select metric_code,
                                      lower(trim(fact)) as fact_key
                                 from official_metric_purpose_evidence_ledger,
                                      jsonb_array_elements_text(runtime_facts_json::jsonb) as fact
                                where aggregate_run_id = ?
                                  and customer_visible = true
                                  and coalesce(trim(fact), '') <> ''
                                group by metric_code, lower(trim(fact))
                               having count(distinct check_code) > 1
                         )
                         group by metric_code, fact_key
                         order by metric_code, fact_key
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId);
        return rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String firstCustomerVisiblePurposeStateOffender(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select location
                          from (
                                select 'purpose:' || metric_code || '.' || check_code || '=' || coalesce(purpose_result, '') as location, created_at
                                  from official_metric_purpose_evaluation_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and upper(coalesce(purpose_result, '')) not in (
                                       'INPUT_NOT_READY',
                                       'NOT_APPLICABLE',
                                       'PURPOSE_PASSED',
                                       'PURPOSE_FAILED'
                                   )
                                union all
                                select 'purpose_evidence:' || metric_code || '.' || check_code || '=' || coalesce(purpose_result, '') as location, created_at
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and upper(coalesce(purpose_result, '')) not in (
                                       'INPUT_NOT_READY',
                                       'NOT_APPLICABLE',
                                       'PURPOSE_PASSED',
                                       'PURPOSE_FAILED'
                                   )
                               ) offenders
                         order by created_at desc
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId);
        return rows == null || rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String firstCustomerVisiblePurposeLedgerTechnicalLocation(String aggregateRunId) {

        List<String> rows = jdbcTemplate.queryForList("""
                        select location
                          from (
                                select 'purpose.actual_value:' || metric_code || '.' || check_code as location, created_at
                                  from official_metric_purpose_evaluation_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                    and (
                                         actual_value ilike '%Evidence:%'
                                         or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or actual_value like '확인된 값:%'
                                          or actual_value like '%실제 프롬프트에서 확인된 값은'
                                          or actual_value like '%확인된 근거:%'
                                          or actual_value like '%검사 대상 항목%'
                                          or actual_value like '% 생략됨'
                                     )
                                  union all
                                 select 'purpose.next_action:' || metric_code || '.' || check_code as location, created_at
                                   from official_metric_purpose_evaluation_ledger
                                  where aggregate_run_id = ?
                                    and customer_visible = true
                                    and (
                                          next_action ilike '%Evidence:%'
                                          or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                          or next_action like '조치:%'
                                          or next_action like '%누락된 항목%'
                                     )
                                  union all
                                 select 'purpose.reverify_criterion:' || metric_code || '.' || check_code as location, created_at
                                   from official_metric_purpose_evaluation_ledger
                                  where aggregate_run_id = ?
                                    and customer_visible = true
                                    and (
                                          reverify_criterion ilike '%Evidence:%'
                                          or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                          or reverify_criterion like '재검증 기준:%'
                                          or reverify_criterion like '%누락된 항목%'
                                     )
                                  union all
                                 select 'purpose_evidence.evidence_value:' || metric_code || '.' || check_code as location, created_at
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and (
                                        evidence_value ilike '%Evidence:%'
                                        or evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                   )
                                 union all
                                 select 'prompt_quality_issue:' || metric_code || '.' || failed_check as location, detected_at as created_at
                                   from prompt_quality_issue
                                  where aggregate_run_id = ?
                                    and (
                                         actual_value ilike '%Evidence:%'
                                        or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                        or next_action ilike '%Evidence:%'
                                        or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                        or reverify_criterion ilike '%Evidence:%'
                                         or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                    )
                                 union all
                                 select 'actual_prompt_problem:' || field_key as location, created_at
                                   from official_actual_prompt_problem_ledger
                                  where aggregate_run_id = ?
                                    and (
                                         prompt_value ilike '%Evidence:%'
                                         or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or expected_state ilike '%Evidence:%'
                                         or expected_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or expected_state like '문제:%'
                                         or actual_state ilike '%Evidence:%'
                                         or actual_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or actual_state like '확인된 값:%'
                                         or fix_action ilike '%Evidence:%'
                                         or fix_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or reverify_criterion_detail ilike '%Evidence:%'
                                         or reverify_criterion_detail ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                    )
                                 union all
                                 select 'prompt_comparison:' || field_key as location, created_at
                                   from official_verification_prompt_comparison
                                  where aggregate_run_id = ?
                                    and (
                                         prompt_value ilike '%Evidence:%'
                                         or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or prompt_value like '확인된 값:%'
                                         or official_fact_value ilike '%Evidence:%'
                                         or official_fact_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or official_fact_value like '문제:%'
                                         or sealed_evidence_value ilike '%Evidence:%'
                                         or sealed_evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                    )
                               ) offenders
                         order by created_at desc
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId);
        return rows == null || rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

}
