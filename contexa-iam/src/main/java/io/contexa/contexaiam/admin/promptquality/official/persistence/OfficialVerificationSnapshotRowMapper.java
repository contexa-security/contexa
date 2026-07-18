package io.contexa.contexaiam.admin.promptquality.official.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorReverificationResult;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class OfficialVerificationSnapshotRowMapper {

    private final ObjectMapper objectMapper;

    public OfficialVerificationSnapshotRowMapper(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }
    OperatorMetricSnapshot metricSnapshot(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorMetricSnapshot(
                rs.getString("aggregate_run_id"),
                rs.getString("official_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("metric_code"),
                rs.getString("metric_name"),
                rs.getString("metric_group"),
                rs.getDouble("score"),
                rs.getString("state"),
                rs.getString("severity"),
                rs.getInt("passed_checks"),
                rs.getInt("total_checks"),
                rs.getInt("failed_check_count"),
                rs.getString("operator_title"),
                rs.getString("operator_summary"),
                rs.getString("primary_failure_reason"),
                rs.getString("remediation_owner"),
                rs.getString("next_action"),
                rs.getString("reverify_criterion"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    OperatorFinding finding(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorFinding(
                rs.getString("finding_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("official_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("issue_id"),
                rs.getString("metric_code"),
                rs.getString("check_code"),
                rs.getString("severity"),
                rs.getString("operator_title"),
                rs.getString("operator_summary"),
                rs.getString("problem_statement"),
                rs.getString("root_cause"),
                rs.getString("affected_target"),
                rs.getString("operator_reason"),
                rs.getString("evidence_summary"),
                rs.getString("evidence_path"),
                rs.getString("expected_value"),
                rs.getString("actual_value"),
                rs.getString("expected_result"),
                rs.getString("actual_result"),
                rs.getString("impact"),
                rs.getString("remediation_owner"),
                rs.getString("next_action"),
                rs.getString("reverify_criterion"),
                rs.getString("customer_visible_severity"),
                rs.getString("related_process_step"),
                rs.getString("comparison_field_key"),
                rs.getString("comparison_state"),
                rs.getString("prompt_location"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    OperatorRemediationGroup remediationGroup(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorRemediationGroup(
                rs.getString("group_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("root_cause_key"),
                rs.getString("remediation_owner"),
                rs.getString("operator_title"),
                rs.getString("operator_reason"),
                rs.getString("next_action"),
                rs.getString("reverify_criterion"),
                splitCsv(rs.getString("affected_metric_codes")),
                splitCsv(rs.getString("affected_check_codes")),
                rs.getInt("finding_count"),
                rs.getString("related_process_step"),
                splitCsv(rs.getString("comparison_field_keys")),
                splitCsv(rs.getString("prompt_locations")),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    OfficialVerificationPromptComparison promptComparison(ResultSet rs, int rowNum) throws SQLException {
        return new OfficialVerificationPromptComparison(
                rs.getString("field_key"),
                rs.getString("field_label"),
                rs.getString("sealed_evidence_value"),
                rs.getString("prompt_value"),
                rs.getString("official_fact_value"),
                rs.getString("state"),
                rs.getString("state_label"),
                rs.getString("meaning"),
                splitCsv(rs.getString("related_metric_codes")),
                splitCsv(rs.getString("related_check_codes")),
                splitCsv(rs.getString("related_finding_ids")),
                splitCsv(rs.getString("related_issue_ids")),
                splitCsv(rs.getString("related_remediation_group_ids")),
                rs.getString("prompt_location"),
                rs.getString("evidence_source"),
                rs.getString("recommended_owner"),
                rs.getString("canonical_source"));
    }

    OfficialActualPromptProblem storedActualPromptProblem(ResultSet rs, int rowNum) throws SQLException {
        return new OfficialActualPromptProblem(
                rs.getString("problem_id"),
                rs.getString("package_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("field_key"),
                rs.getString("problem_type"),
                rs.getString("prompt_section"),
                rs.getString("prompt_label"),
                rs.getString("prompt_value"),
                rs.getString("source_field_path"),
                rs.getString("sealed_evidence_path"),
                rs.getString("expected_state"),
                rs.getString("actual_state"),
                rs.getString("severity"),
                splitCsv(rs.getString("affected_metric_codes")),
                rs.getString("remediation_owner"),
                rs.getString("quality_question"),
                rs.getString("why_it_matters"),
                rs.getString("fix_action"),
                rs.getString("reverify_criterion_detail"),
                splitCustomerDisplayJsonArray(rs.getString("runtime_facts_json"), "runtimeFacts"),
                splitCustomerDisplayJsonArray(rs.getString("context_items_json"), "contextItems"));
    }

    OperatorPurposeEvidence purposeEvidenceRow(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorPurposeEvidence(
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("metric_code"),
                rs.getString("check_code"),
                rs.getString("contract_version"),
                rs.getString("signal_key"),
                rs.getString("prompt_location"),
                rs.getString("evidence_value"),
                rs.getString("evidence_hash"),
                rs.getString("interpretation"),
                rs.getString("purpose_result"),
                rs.getBoolean("customer_visible"),
                rs.getString("readiness_scope"),
                splitCustomerDisplayJsonArray(rs.getString("runtime_facts_json"), "runtimeFacts"),
                splitCustomerDisplayJsonArray(rs.getString("context_items_json"), "contextItems"),
                instant(rs.getTimestamp("created_at")));
    }

    OperatorAuditSnapshot auditSnapshot(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorAuditSnapshot(
                rs.getString("snapshot_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("state"),
                rs.getString("state_label"),
                rs.getInt("total_metric_count"),
                rs.getInt("failed_metric_count"),
                rs.getBoolean("certificate_issued"),
                rs.getString("prompt_hash"),
                rs.getString("context_hash"),
                splitJsonArray(rs.getString("blocking_findings_json")),
                splitJsonArray(rs.getString("next_actions_json")),
                rs.getString("payload_json"),
                rs.getString("created_by"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    OperatorReverificationResult reverificationResult(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorReverificationResult(
                rs.getString("result_id"),
                rs.getString("source_package_id"),
                rs.getString("source_aggregate_run_id"),
                rs.getString("fixed_package_id"),
                rs.getString("fixed_aggregate_run_id"),
                rs.getString("source_finding_id"),
                rs.getString("issue_id"),
                rs.getString("metric_code"),
                rs.getString("check_code"),
                rs.getString("reverify_criterion"),
                rs.getString("source_operator_reason"),
                rs.getString("source_expected_value"),
                rs.getString("source_actual_value"),
                rs.getString("fixed_actual_value"),
                rs.getBoolean("resolved"),
                rs.getString("resolution_state"),
                rs.getString("operator_summary"),
                rs.getString("created_by"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private List<String> splitCsv(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String part : value.split(",")) {
            if (StringUtils.hasText(part)) {
                result.add(part.trim());
            }
        }
        return List.copyOf(result);
    }

    private List<String> splitJsonArray(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            return raw.stream()
                    .filter(Objects::nonNull)
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .toList();
        }
        catch (Exception ignored) {
            return List.of(value);
        }
    }

    private List<String> splitCustomerDisplayJsonArray(String value, String nestedKey) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            boolean runtimeFacts = "runtimeFacts".equals(nestedKey);
            for (Object item : raw) {
                if (item instanceof String text) {
                    appendCustomerDisplayItems(result, text, runtimeFacts);
                }
                else if (item instanceof Map<?, ?> map && map.get(nestedKey) != null) {
                    result.addAll(customerDisplayItems(map.get(nestedKey), runtimeFacts));
                }
            }
            return List.copyOf(result);
        }
        catch (Exception ignored) {
            return List.of();
        }
    }

    private List<String> customerDisplayItems(Object value, boolean runtimeFacts) {
        if (value == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                if (item instanceof Map<?, ?> map) {
                    Object nested = map.get(runtimeFacts ? "runtimeFacts" : "contextItems");
                    if (nested != null) {
                        result.addAll(customerDisplayItems(nested, runtimeFacts));
                    }
                }
                else {
                    appendCustomerDisplayItems(result, String.valueOf(item), runtimeFacts);
                }
            }
        }
        else {
            appendCustomerDisplayItems(result, String.valueOf(value), runtimeFacts);
        }
        return List.copyOf(result);
    }

    private void appendCustomerDisplayItems(List<String> items, String value, boolean runtimeFacts) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        String normalized = value.replace("\r\n", "\n").replace('\r', '\n').trim();
        String delimiter = runtimeFacts ? "(?<=\\.)\\s+|\\n+" : "[,\\n]";
        for (String token : normalized.split(delimiter)) {
            String item = token == null ? "" : token.trim();
            if (StringUtils.hasText(item)) {
                appendUnique(items, item);
            }
        }
    }

    private void appendUnique(List<String> values, String value) {
        String candidateKey = normalizeDisplayKey(value);
        boolean exists = values.stream()
                .filter(StringUtils::hasText)
                .map(this::normalizeDisplayKey)
                .anyMatch(candidateKey::equals);
        if (!exists) {
            values.add(value.trim());
        }
    }

    private String normalizeDisplayKey(String value) {
        return value.trim()
                .replaceAll("[\\s\\x{00A0}]+", " ")
                .replaceAll("[.。]+$", "")
                .toLowerCase(Locale.ROOT);
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}