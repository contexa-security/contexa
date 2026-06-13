package io.contexa.contexacore.verification.runtime.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public record FinalPromptSemanticModel(
        FinalPromptSnapshot snapshot,
        Map<String, List<FinalPromptField>> fieldsBySemanticKey,
        Map<String, List<FinalPromptField>> fieldsByNormalizedLabel
) {

    public FinalPromptSemanticModel {
        fieldsBySemanticKey = immutableListMap(fieldsBySemanticKey);
        fieldsByNormalizedLabel = immutableListMap(fieldsByNormalizedLabel);
    }

    public static FinalPromptSemanticModel from(FinalPromptSnapshot snapshot) {
        if (snapshot == null) {
            return empty();
        }
        Map<String, List<FinalPromptField>> bySemanticKey = new LinkedHashMap<>();
        Map<String, List<FinalPromptField>> byLabel = new LinkedHashMap<>();
        for (FinalPromptField field : snapshot.fields()) {
            if (field == null || !StringUtils.hasText(field.label())) {
                continue;
            }
            bySemanticKey.computeIfAbsent(semanticKey(field), ignored -> new ArrayList<>()).add(field);
            byLabel.computeIfAbsent(FinalPromptSnapshot.normalizeLabel(field.label()), ignored -> new ArrayList<>()).add(field);
        }
        return new FinalPromptSemanticModel(snapshot, bySemanticKey, byLabel);
    }

    public static FinalPromptSemanticModel empty() {
        return new FinalPromptSemanticModel(null, Map.of(), Map.of());
    }

    public List<FinalPromptField> fieldsByLabel(String label) {
        if (!StringUtils.hasText(label)) {
            return List.of();
        }
        return fieldsByNormalizedLabel.getOrDefault(FinalPromptSnapshot.normalizeLabel(label), List.of());
    }

    public boolean hasValue(String label) {
        return fieldsByLabel(label).stream()
                .map(FinalPromptField::value)
                .anyMatch(StringUtils::hasText);
    }

    public String firstValue(String... labels) {
        if (labels == null) {
            return null;
        }
        for (String label : labels) {
            for (FinalPromptField field : fieldsByLabel(label)) {
                if (StringUtils.hasText(field.value())) {
                    return field.value().trim();
                }
            }
        }
        return null;
    }

    public static String semanticKey(FinalPromptField field) {
        if (field == null) {
            return "finalUserPrompt.unknown";
        }
        if (StringUtils.hasText(field.semanticKey())) {
            return field.semanticKey();
        }
        return semanticKey(field.section(), field.label());
    }

    public static String semanticKey(String section, String label) {
        return "finalUserPrompt."
                + keyPart(section, "root")
                + "."
                + keyPart(label, "field");
    }

    public static String securityRelevance(String section, String label) {
        String role = attackSignalRole(section, label, "");
        return switch (role) {
            case "PROMPT_FIDELITY_SIGNAL" -> "PROMPT_FIDELITY";
            case "INTERNAL_EXECUTION_SIGNAL" -> "INTERNAL_GATE";
            default -> "ATTACK_DETECTION";
        };
    }

    public static String attackSignalRole(String section, String label, String value) {
        String combined = ((section == null ? "" : section) + " "
                + (label == null ? "" : label) + " "
                + (value == null ? "" : value)).toUpperCase(Locale.ROOT);
        if (containsAny(combined, "COMPACT", "TRUNCATED", "ADDITIONAL", "...")) {
            return "PROMPT_FIDELITY_SIGNAL";
        }
        if (containsAny(combined, "RAG", "DOCUMENT", "RETRIEVAL")) {
            return "RAG_EVIDENCE_SIGNAL";
        }
        if (containsAny(combined, "UNKNOWN", "PROVISIONAL", "LEARNING", "FALLBACK", "THIN",
                "NO_DIRECT_PERSONAL_COMPARABLE", "MISSING KNOWLEDGE", "CONFIDENCEWARNING", "LIMITATION")) {
            return "UNCERTAINTY_BOUNDARY_SIGNAL";
        }
        if (containsAny(combined, "MFA", "FAILEDLOGIN", "NEWDEVICE", "NEWSESSION", "NEWUSER",
                "AUTHENTICATION", "ASSURANCE")) {
            return "AUTHENTICATION_SIGNAL";
        }
        if (containsAny(combined, "AUTHORIZATION", "EFFECTIVEROLES", "EFFECTIVEPERMISSIONS",
                "ROLE", "PERMISSION", "SCOPE")) {
            return "AUTHORIZATION_SIGNAL";
        }
        if (containsAny(combined, "RESOURCE", "SENSITIVITY", "SENSITIVERESOURCE", "ACTIONFAMILY")) {
            return "RESOURCE_RISK_SIGNAL";
        }
        if (containsAny(combined, "SESSION", "PREVIOUSPATH", "INTERVAL", "BURST", "SEQUENCE")) {
            return "SESSION_BEHAVIOR_SIGNAL";
        }
        if (containsAny(combined, "BASELINE", "OBSERVED", "CURRENTVS", "STRONGESTCURRENT",
                "PRESENTINOBSERVED", "COMBINATION")) {
            return "BASELINE_CHANGE_SIGNAL";
        }
        if (containsAny(combined, "APPROVAL", "FRICTION", "CHALLENGE", "DENIED")) {
            return "FRICTION_APPROVAL_SIGNAL";
        }
        if (containsAny(combined, "DELEGATED", "OBJECTIVE")) {
            return "DELEGATION_SIGNAL";
        }
        if (containsAny(combined, "HASH", "LINEAGE", "MANIFEST")) {
            return "INTERNAL_EXECUTION_SIGNAL";
        }
        return "CONTEXT_FACT_SIGNAL";
    }

    private static boolean containsAny(String value, String... needles) {
        if (!StringUtils.hasText(value) || needles == null) {
            return false;
        }
        for (String needle : needles) {
            if (StringUtils.hasText(needle) && value.contains(needle.toUpperCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String keyPart(String value, String fallback) {
        if (!StringUtils.hasText(value)) {
            return fallback;
        }
        String normalized = value.trim()
                .replaceAll("[^\\p{L}\\p{N}]+", "_")
                .replaceAll("^_+|_+$", "")
                .toLowerCase(Locale.ROOT);
        return normalized.isBlank() ? fallback : normalized;
    }

    private static Map<String, List<FinalPromptField>> immutableListMap(Map<String, List<FinalPromptField>> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, List<FinalPromptField>> result = new LinkedHashMap<>();
        source.forEach((key, value) -> result.put(key, value == null ? List.of() : List.copyOf(value)));
        return Map.copyOf(result);
    }
}
