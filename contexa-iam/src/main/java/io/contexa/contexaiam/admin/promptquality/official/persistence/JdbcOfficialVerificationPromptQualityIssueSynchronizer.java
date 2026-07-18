package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptQualityIssueSynchronizer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.Objects;

public final class JdbcOfficialVerificationPromptQualityIssueSynchronizer
        implements OfficialVerificationPromptQualityIssueSynchronizer {

    private static final String SYNCHRONIZE_SQL = """
            update prompt_quality_issue i
               set severity = p.severity,
                   issue_title = p.prompt_label,
                   plain_problem = p.prompt_value,
                   llm_judgement_risk = p.why_it_matters,
                   remediation_target = p.remediation_owner,
                   next_action = p.fix_action,
                   metric_code = split_part(p.affected_metric_codes, ',', 1),
                   package_id = p.package_id,
                   aggregate_run_id = p.aggregate_run_id,
                   failed_package_id = p.package_id,
                   failed_check = p.prompt_label,
                   expected_value = p.expected_state,
                   actual_value = p.actual_state,
                   evidence_source = p.sealed_evidence_path,
                   prompt_location = p.source_field_path,
                   root_cause_type = p.problem_type,
                   production_target_type = i.production_target_type,
                   production_target_ref = p.remediation_owner,
                   http_method = i.http_method,
                   reverify_criterion = p.reverify_criterion_detail,
                   expected_prompt_delta_json = jsonb_build_object(
                       'problem', p.prompt_label,
                       'currentState', p.actual_state,
                       'targetState', p.expected_state,
                       'impact', p.why_it_matters,
                       'resolutionAction', p.fix_action,
                       'reverifyCondition', p.reverify_criterion_detail,
                       'owner', p.remediation_owner,
                       'metric', p.affected_metric_codes
                   )::text
              from official_actual_prompt_problem_ledger p
              join sealed_evidence_package sealed on sealed.package_id = p.package_id
             where p.package_id = ?
               and p.aggregate_run_id = ?
               and sealed.tenant_id = ?
               and i.issue_id = p.problem_id
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationPromptQualityIssueSynchronizer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void synchronize(String tenantId, String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(tenantId)
                || !StringUtils.hasText(packageId)
                || !StringUtils.hasText(aggregateRunId)) {
            return;
        }
        jdbcTemplate.update(SYNCHRONIZE_SQL, packageId.trim(), aggregateRunId.trim(), tenantId.trim());
    }
}
