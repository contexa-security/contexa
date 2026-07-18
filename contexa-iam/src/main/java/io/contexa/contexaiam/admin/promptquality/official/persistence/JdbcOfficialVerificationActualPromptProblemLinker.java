package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationActualPromptProblemLinker;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.Objects;

public final class JdbcOfficialVerificationActualPromptProblemLinker
        implements OfficialVerificationActualPromptProblemLinker {

    private static final String LINK_PURPOSE_SQL = """
            update official_actual_prompt_problem_ledger p
               set purpose_evaluation_id = e.id,
                   contract_version_id = coalesce(
                       p.contract_version_id, c.id,
                       (
                           select c2.id from official_metric_evaluation_contract c2
                            where c2.contract_version = e.contract_version
                              and upper(c2.metric_code) = upper(e.metric_code)
                              and (c2.check_code = e.check_code or c2.issue_key = e.issue_key or c2.issue_key = p.field_key)
                            order by c2.id desc limit 1
                       )
                   ),
                   quality_question = coalesce(nullif(trim(p.quality_question), ''), e.decision_utility),
                   why_it_matters = coalesce(nullif(trim(p.why_it_matters), ''), e.purpose_statement),
                   fix_action = coalesce(nullif(trim(p.fix_action), ''), e.next_action),
                   reverify_criterion_detail = coalesce(
                       nullif(trim(p.reverify_criterion_detail), ''), e.reverify_criterion)
              from official_metric_purpose_evaluation_ledger e
              left join official_metric_evaluation_contract c
                on c.contract_version = e.contract_version
               and upper(c.metric_code) = upper(e.metric_code)
               and (c.check_code = e.check_code or c.issue_key = e.issue_key)
             where p.aggregate_run_id = ?
               and p.package_id = ?
               and exists (
                   select 1 from sealed_evidence_package sealed
                    where sealed.package_id = p.package_id and sealed.tenant_id = ?
               )
               and e.aggregate_run_id = p.aggregate_run_id
               and e.customer_visible = true
               and (coalesce(nullif(trim(e.issue_key), ''), e.check_code) = p.field_key or c.issue_key = p.field_key)
               and (p.purpose_evaluation_id is null or p.contract_version_id is null)
            """;
    private static final String MARK_BLOCKING_FIELDS_SQL = """
            update official_prompt_field_value_ledger v
               set blocking_candidate = true
              from official_actual_prompt_problem_ledger p
             where p.aggregate_run_id = ?
               and p.package_id = ?
               and v.aggregate_run_id = p.aggregate_run_id
               and v.package_id = p.package_id
               and exists (
                   select 1 from sealed_evidence_package sealed
                    where sealed.package_id = p.package_id and sealed.tenant_id = ?
               )
               and upper(v.prompt_stage) = 'FINAL_USER'
               and p.current_result = true
               and p.severity = 'BLOCKING'
               and (
                   v.field_key = p.field_key
                   or (nullif(trim(coalesce(v.prompt_label, '')), '') is not null and v.prompt_label = p.prompt_label)
                   or (
                       nullif(trim(coalesce(v.prompt_label, '')), '') is not null
                       and position(v.prompt_label in coalesce(p.actual_state, '')) > 0
                   )
               )
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationActualPromptProblemLinker(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void link(String aggregateRunId, String packageId, String tenantId) {
        if (!StringUtils.hasText(aggregateRunId)
                || !StringUtils.hasText(packageId)
                || !StringUtils.hasText(tenantId)) {
            return;
        }
        Object[] arguments = {aggregateRunId.trim(), packageId.trim(), tenantId.trim()};
        jdbcTemplate.update(LINK_PURPOSE_SQL, arguments);
        jdbcTemplate.update(MARK_BLOCKING_FIELDS_SQL, arguments);
    }
}
