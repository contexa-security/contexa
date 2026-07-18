package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationActualPromptProblemRepository;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public final class JdbcOfficialVerificationActualPromptProblemRepository implements OfficialVerificationActualPromptProblemRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationActualPromptProblemRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }
    @Override
    public List<OfficialActualPromptProblem> findByAggregateRunId(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select problem_id, package_id, aggregate_run_id, field_key, problem_type,
                               prompt_section, prompt_label, prompt_value, source_field_path,
                               sealed_evidence_path, expected_state, actual_state, severity,
                               affected_metric_codes, remediation_owner, quality_question,
                               why_it_matters, fix_action, reverify_criterion_detail,
                               coalesce((
                                   select evidence.runtime_facts_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as runtime_facts_json,
                               coalesce((
                                   select evidence.context_items_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_actual_prompt_problem_ledger p
                         where aggregate_run_id = ?
                           and upper(coalesce(problem_type, '')) <> 'INPUT_NOT_READY'
                          order by case when severity = 'BLOCKING' then 0 else 1 end,
                                   prompt_label asc, field_key asc, problem_id asc
                        """,
                rowMapper::storedActualPromptProblem,
                aggregateRunId);
    }

    @Override
    public List<OfficialActualPromptProblem> findByAggregateRunIds(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select problem_id, package_id, aggregate_run_id, field_key, problem_type,
                               prompt_section, prompt_label, prompt_value, source_field_path,
                               sealed_evidence_path, expected_state, actual_state, severity,
                               affected_metric_codes, remediation_owner, quality_question,
                               why_it_matters, fix_action, reverify_criterion_detail,
                               coalesce((
                                   select evidence.runtime_facts_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as runtime_facts_json,
                               coalesce((
                                   select evidence.context_items_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_actual_prompt_problem_ledger p
                         where aggregate_run_id in (%s)
                           and upper(coalesce(problem_type, '')) <> 'INPUT_NOT_READY'
                          order by aggregate_run_id asc,
                                   case when severity = 'BLOCKING' then 0 else 1 end,
                                  prompt_label asc, field_key asc, problem_id asc
                        """.formatted(placeholders(aggregateRunIds)),
                rowMapper::storedActualPromptProblem,
                aggregateRunIds.toArray());
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }
}