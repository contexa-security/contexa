package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationActualPromptProblemWriter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class JdbcOfficialVerificationActualPromptProblemWriter
        implements OfficialVerificationActualPromptProblemWriter {

    private static final String INSERT_SQL = """
            insert into official_actual_prompt_problem_ledger (
                problem_id, package_id, aggregate_run_id, field_key, problem_type,
                prompt_section, prompt_label, prompt_value, source_field_path,
                sealed_evidence_path, expected_state, actual_state, severity,
                affected_metric_codes, remediation_owner, quality_question,
                why_it_matters, fix_action, reverify_criterion_detail,
                purpose_evaluation_id, contract_version_id, created_at
            ) values (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                (
                    select e.id from official_metric_purpose_evaluation_ledger e
                     where e.aggregate_run_id = ? and upper(e.metric_code) = ?
                       and e.customer_visible = true
                       and (e.issue_key = ? or e.check_code = ? or e.issue_key = ?)
                     order by e.id desc limit 1
                ),
                (
                    select c.id
                      from official_metric_evaluation_contract c
                      join official_metric_purpose_evaluation_ledger e
                        on e.contract_version = c.contract_version
                       and upper(e.metric_code) = upper(c.metric_code)
                       and (e.check_code = c.check_code or e.issue_key = c.issue_key or c.issue_key = ?)
                     where e.aggregate_run_id = ? and upper(e.metric_code) = ?
                       and e.customer_visible = true
                       and (e.issue_key = ? or e.check_code = ? or c.issue_key = ?)
                     order by c.id desc limit 1
                ),
                ?
            )
            on conflict (problem_id) do update set
                package_id = excluded.package_id,
                aggregate_run_id = excluded.aggregate_run_id,
                field_key = excluded.field_key,
                problem_type = excluded.problem_type,
                prompt_section = excluded.prompt_section,
                prompt_label = excluded.prompt_label,
                prompt_value = excluded.prompt_value,
                source_field_path = excluded.source_field_path,
                sealed_evidence_path = excluded.sealed_evidence_path,
                expected_state = excluded.expected_state,
                actual_state = excluded.actual_state,
                severity = excluded.severity,
                affected_metric_codes = excluded.affected_metric_codes,
                remediation_owner = excluded.remediation_owner,
                quality_question = excluded.quality_question,
                why_it_matters = excluded.why_it_matters,
                fix_action = excluded.fix_action,
                reverify_criterion_detail = excluded.reverify_criterion_detail,
                purpose_evaluation_id = excluded.purpose_evaluation_id,
                contract_version_id = excluded.contract_version_id,
                created_at = excluded.created_at
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationActualPromptProblemWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(String aggregateRunId, String packageId, List<Command> problems) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId)) {
            return;
        }
        for (Command problem : problems == null ? List.<Command>of() : problems) {
            insertOne(aggregateRunId, packageId, problem);
        }
    }

    private void insertOne(String aggregateRunId, String packageId, Command problem) {
        String primaryMetricCode = problem.metricCodes() == null || problem.metricCodes().isEmpty()
                ? ""
                : normalize(problem.metricCodes().get(0));
        jdbcTemplate.update(INSERT_SQL,
                fit(problem.problemId(), 256), fit(packageId, 128), fit(aggregateRunId, 256),
                fit(problem.fieldKey(), 512), fit(problem.problemType(), 64), fit(problem.promptSection(), 256),
                fit(problem.promptLabel(), 256), safe(problem.promptValue()), fit(problem.sourceFieldPath(), 1024),
                fit(problem.sealedEvidencePath(), 1024), problem.expectedState(), problem.actualState(),
                fit(problem.severity(), 32), fit(String.join(",", problem.metricCodes()), 512),
                fit(safe(problem.remediationOwner()), 128), safe(problem.qualityQuestion()),
                safe(problem.whyItMatters()), safe(problem.fixAction()), safe(problem.reverifyCriterion()),
                aggregateRunId, primaryMetricCode, fit(problem.fieldKey(), 512), fit(problem.problemType(), 128),
                fit(problem.sourceFieldPath(), 512), fit(problem.fieldKey(), 512), aggregateRunId, primaryMetricCode,
                fit(problem.fieldKey(), 512), fit(problem.problemType(), 128), fit(problem.fieldKey(), 512),
                Timestamp.from(Instant.now()));
    }

    private String normalize(String value) {
        return safe(value).trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }
}
