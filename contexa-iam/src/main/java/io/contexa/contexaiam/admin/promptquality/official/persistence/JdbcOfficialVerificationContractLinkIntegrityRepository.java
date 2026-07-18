package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationContractLinkIntegrityRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public final class JdbcOfficialVerificationContractLinkIntegrityRepository
        implements OfficialVerificationContractLinkIntegrityRepository {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationContractLinkIntegrityRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void assertActualPromptProblemLedgerReferences(String aggregateRunId) {
        int missingContract = count("""
                select count(*) from official_actual_prompt_problem_ledger
                 where aggregate_run_id = ? and severity = 'BLOCKING'
                   and (purpose_evaluation_id is null or contract_version_id is null)
                """, aggregateRunId);
        if (missingContract > 0) {
            throw new IllegalStateException("Actual prompt problem ledger is missing purpose contract linkage. aggregateRunId="
                    + aggregateRunId + ", missingContractCount=" + missingContract
                    + ", firstOffender=" + firstProblemWithoutPurposeContract(aggregateRunId));
        }
        int comparisonsWithoutProblem = count("""
                select count(*) from (
                    select distinct field_key from official_verification_prompt_comparison
                     where aggregate_run_id = ? and nullif(trim(field_key), '') is not null
                       and (field_key like 'finalUserPrompt.%' or field_key like 'finalSystemPrompt.%')
                       and (
                           state like 'FINAL_PROMPT_%'
                           or state in ('PROMPT_MISSING', 'FACT_MISSING', 'VALUE_MISMATCH', 'CONTRACT_MISMATCH',
                               'REQUIRED_MISSING', 'CONDITIONAL_REQUIRED_MISSING', 'UNKNOWN_WITHOUT_REASON',
                               'PROMPT_COMPACTED_SIGNAL', 'PRODUCER_NOT_AVAILABLE', 'PROVISIONAL_EVIDENCE',
                               'NO_DIRECT_COMPARABLE', 'BASELINE_MISMATCH_SIGNAL')
                       )
                       and canonical_source <> 'OFFICIAL_FINDING'
                    except
                    select distinct field_key from official_actual_prompt_problem_ledger
                     where aggregate_run_id = ? and severity = 'BLOCKING' and nullif(trim(field_key), '') is not null
                ) missing_actual_prompt_problem
                """, aggregateRunId, aggregateRunId);
        if (comparisonsWithoutProblem > 0) {
            throw new IllegalStateException("Prompt comparison blocking rows are not fully represented in the actual prompt problem ledger. aggregateRunId="
                    + aggregateRunId + ", missingProblemCount=" + comparisonsWithoutProblem);
        }
        int findingsWithoutProblem = count("""
                select count(*) from (
                    select check_code from official_verification_operator_finding
                     where aggregate_run_id = ? and check_code is not null and trim(check_code) <> ''
                    except
                    select problem_id from official_actual_prompt_problem_ledger
                     where aggregate_run_id = ? and severity = 'BLOCKING'
                ) missing_actual_prompt_problem
                """, aggregateRunId, aggregateRunId);
        if (findingsWithoutProblem > 0) {
            throw new IllegalStateException("12 official metric findings must reference actual prompt problem ledger problem_id values. aggregateRunId="
                    + aggregateRunId + ", missingProblemReferenceCount=" + findingsWithoutProblem);
        }
    }

    @Override
    public Set<String> registeredMetricCodes() {
        return normalizedSet(jdbcTemplate.queryForList("""
                select p.metric_code from official_metric_purpose_contract p
                join official_metric_contract_version v on v.contract_version = p.contract_version and v.active = true
                """, String.class));
    }

    @Override
    public Set<String> registeredMetricCheckCodes() {
        List<String> rows = jdbcTemplate.queryForList("""
                select e.metric_code || '|' || e.check_code from official_metric_evaluation_contract e
                join official_metric_contract_version v on v.contract_version = e.contract_version and v.active = true
                """, String.class);
        Set<String> result = new LinkedHashSet<>();
        for (String row : rows == null ? List.<String>of() : rows) {
            String[] parts = safe(row).split("\\|", 2);
            if (parts.length == 2 && StringUtils.hasText(parts[0]) && StringUtils.hasText(parts[1])) {
                result.add(normalize(parts[0]) + "|" + normalize(parts[1]));
            }
        }
        return Set.copyOf(result);
    }

    @Override
    public Optional<CheckDefinitionLink> findMetricCheckDefinition(String metricCode, String checkCode) {
        try {
            return jdbcTemplate.query("""
                    select e.issue_key, e.issue_key as prompt_location, e.readiness_scope
                      from official_metric_evaluation_contract e
                      join official_metric_contract_version v
                        on v.contract_version = e.contract_version and v.active = true
                     where e.metric_code = ? and e.check_code = ?
                     order by e.created_at desc, e.id desc limit 1
                    """, (rs, rowNum) -> new CheckDefinitionLink(
                        rs.getString("issue_key"), rs.getString("prompt_location"), rs.getString("readiness_scope")),
                    metricCode, checkCode).stream().findFirst();
        }
        catch (DataAccessException ignored) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<CheckDefinitionLink> findActualPromptProblemLink(
            String aggregateRunId, String problemId, String issueKey, String contractIssueKey, String source) {
        try {
            return jdbcTemplate.query("""
                    select field_key, prompt_section, source_field_path
                      from official_actual_prompt_problem_ledger
                     where aggregate_run_id = ?
                       and (problem_id = ? or field_key = ? or field_key = ? or field_key = ?)
                     order by case when severity = 'BLOCKING' then 0 else 1 end, created_at desc limit 1
                    """, (rs, rowNum) -> new CheckDefinitionLink(
                        rs.getString("field_key"),
                        firstNonBlank(rs.getString("source_field_path"), rs.getString("prompt_section"), "userPrompt"),
                        "OFFICIAL_VERIFICATION"),
                    aggregateRunId, problemId, issueKey, contractIssueKey, source).stream().findFirst();
        }
        catch (DataAccessException ignored) {
            return Optional.empty();
        }
    }

    private String firstProblemWithoutPurposeContract(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                select field_key || '|' || problem_type || '|metrics=' || affected_metric_codes
                  from official_actual_prompt_problem_ledger
                 where aggregate_run_id = ? and severity = 'BLOCKING'
                   and (purpose_evaluation_id is null or contract_version_id is null)
                 order by created_at desc, field_key asc limit 1
                """, String.class, aggregateRunId);
        return rows == null || rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private Set<String> normalizedSet(List<String> rows) {
        Set<String> result = new LinkedHashSet<>();
        for (String row : rows == null ? List.<String>of() : rows) {
            if (StringUtils.hasText(row)) {
                result.add(normalize(row));
            }
        }
        return Set.copyOf(result);
    }

    private int count(String sql, Object... arguments) {
        Integer value = jdbcTemplate.queryForObject(sql, Integer.class, arguments);
        return value == null ? 0 : value;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return safe(value).trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}