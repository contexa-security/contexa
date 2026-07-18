package io.contexa.contexaiam.admin.promptquality.official.persistence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialPromptFieldDefinitionWriter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class JdbcOfficialPromptFieldDefinitionWriter implements OfficialPromptFieldDefinitionWriter {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public JdbcOfficialPromptFieldDefinitionWriter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void upsertFrom(SealedEvidencePackage evidencePackage) {
        if (evidencePackage == null) {
            return;
        }
        Map<String, Object> manifest = parseJson(evidencePackage.getPromptEvidenceManifestJson());
        if (manifest.get("fields") instanceof List<?> fields) {
            fields.stream()
                    .filter(Map.class::isInstance)
                    .map(Map.class::cast)
                    .forEach(this::upsertManifestField);
        }
        if (manifest.get("fieldStateLedger") instanceof List<?> states) {
            states.stream()
                    .filter(Map.class::isInstance)
                    .map(Map.class::cast)
                    .forEach(this::upsertStateField);
        }
    }

    private void upsertManifestField(Map<?, ?> row) {
        String fieldKey = text(row.get("fieldKey"));
        if (!StringUtils.hasText(fieldKey)) {
            return;
        }
        Object promptLabels = row.get("promptLabels");
        String promptLabel = promptLabels instanceof List<?> labels && !labels.isEmpty()
                ? text(labels.get(0))
                : text(row.get("displayName"));
        upsert(new FieldDefinition(
                fieldKey,
                defaultText(row.get("evidenceSection"), "SEALED_EVIDENCE"),
                null,
                null,
                defaultText(row.get("evidencePath"), fieldKey),
                "userPrompt",
                promptLabel,
                null,
                defaultText(row.get("requiredLevel"), "P1_REQUIRED_WITH_DECLARED_ABSENCE"),
                defaultText(row.get("projectionPolicy"), "MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY"),
                defaultText(row.get("applicabilityRule"), "APPLIES_TO_POST_AUTH_ZERO_TRUST_LLM_DECISION"),
                defaultText(row.get("qualityRelevance"), "LLM_DECISION_CONTRACT"),
                String.join(",", stringList(row.get("metricCodes"))),
                defaultText(row.get("producerCode"), text(row.get("producer"))),
                text(row.get("notApplicableRule"))));
    }

    private void upsertStateField(Map<?, ?> row) {
        String fieldKey = text(row.get("fieldKey"));
        if (!StringUtils.hasText(fieldKey)) {
            return;
        }
        String sourceClass = text(row.get("sourceClass"));
        upsert(new FieldDefinition(
                fieldKey,
                defaultText(row.get("sourceType"), "SOURCE_CONTEXT"),
                sourcePackage(sourceClass),
                sourceClass,
                defaultText(row.get("sourceFieldPath"), fieldKey),
                defaultText(row.get("promptSection"), text(row.get("promptPresenceState"))),
                defaultText(row.get("promptLabel"), fieldKey),
                text(row.get("valueType")),
                defaultText(row.get("requiredPolicy"), "SOURCE_STATE_CAPTURED"),
                defaultText(row.get("projectionPolicy"), "SEALED_SOURCE_ONLY"),
                defaultText(row.get("applicabilityRule"), "ALWAYS_CAPTURE_SOURCE_STATE"),
                defaultText(row.get("qualityRelevance"), "AUDIT_ONLY_SEALED_SOURCE"),
                String.join(",", stringList(row.get("metricCodes"))),
                defaultText(row.get("remediationOwner"), text(row.get("producerStatus"))),
                text(row.get("notApplicableRule"))));
    }

    private void upsert(FieldDefinition field) {
        jdbcTemplate.update("""
                        insert into official_prompt_field_definition (
                            field_key, source_model, source_package, source_class, source_field_path,
                            prompt_section, prompt_label, value_type,
                            required_policy, projection_policy, applicability_rule, quality_relevance,
                            metric_codes, remediation_owner, not_applicable_rule, is_active, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        on conflict (field_key) do update set
                            source_model = excluded.source_model,
                            source_package = excluded.source_package,
                            source_class = excluded.source_class,
                            source_field_path = excluded.source_field_path,
                            prompt_section = excluded.prompt_section,
                            prompt_label = excluded.prompt_label,
                            value_type = excluded.value_type,
                            required_policy = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.required_policy
                                else excluded.required_policy
                            end,
                            projection_policy = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.projection_policy
                                else excluded.projection_policy
                            end,
                            applicability_rule = excluded.applicability_rule,
                            quality_relevance = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.quality_relevance
                                else excluded.quality_relevance
                            end,
                            metric_codes = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.metric_codes
                                else excluded.metric_codes
                            end,
                            remediation_owner = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.remediation_owner
                                else excluded.remediation_owner
                            end,
                            not_applicable_rule = excluded.not_applicable_rule,
                            is_active = true
                        """,
                fit(field.fieldKey(), 512),
                fit(firstNonBlank(field.sourceModel(), "SOURCE_CONTEXT"), 256),
                fit(field.sourcePackage(), 512),
                fit(field.sourceClass(), 512),
                fit(firstNonBlank(field.sourceFieldPath(), field.fieldKey()), 1024),
                fit(field.promptSection(), 128),
                fit(field.promptLabel(), 256),
                fit(field.valueType(), 256),
                fit(firstNonBlank(field.requiredPolicy(), "SOURCE_STATE_CAPTURED"), 64),
                fit(firstNonBlank(field.projectionPolicy(), "SEALED_SOURCE_ONLY"), 64),
                fit(field.applicabilityRule(), 256),
                fit(firstNonBlank(field.qualityRelevance(), "AUDIT_ONLY_SEALED_SOURCE"), 64),
                fit(field.metricCodes(), 256),
                fit(field.remediationOwner(), 128),
                defaultText(field.notApplicableRule(), ""),
                Timestamp.from(Instant.now()));
    }

    private Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : parsed;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(this::text).filter(StringUtils::hasText).distinct().toList();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            return Arrays.stream(text.split(",")).map(String::trim).filter(StringUtils::hasText).toList();
        }
        return List.of();
    }

    private String text(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private String defaultText(Object value, String fallback) {
        return firstNonBlank(text(value), fallback);
    }

    private String firstNonBlank(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private String sourcePackage(String sourceClass) {
        int lastDot = StringUtils.hasText(sourceClass) ? sourceClass.lastIndexOf('.') : -1;
        return lastDot > 0 ? sourceClass.substring(0, lastDot) : null;
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || maxLength <= 0) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }

    private record FieldDefinition(
            String fieldKey,
            String sourceModel,
            String sourcePackage,
            String sourceClass,
            String sourceFieldPath,
            String promptSection,
            String promptLabel,
            String valueType,
            String requiredPolicy,
            String projectionPolicy,
            String applicabilityRule,
            String qualityRelevance,
            String metricCodes,
            String remediationOwner,
            String notApplicableRule) {
    }
}
