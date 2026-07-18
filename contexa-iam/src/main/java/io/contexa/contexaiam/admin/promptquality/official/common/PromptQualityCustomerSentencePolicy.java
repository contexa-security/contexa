package io.contexa.contexaiam.admin.promptquality.official.common;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PromptQualityCustomerSentencePolicy {

    private static final int MAX_CUSTOMER_SENTENCE_LENGTH = 1_200;
    private static final Pattern RAW_JSON_FIELD = Pattern.compile("(?s).*\\{\\s*\"[^\"]+\"\\s*:.*");
    private static final Pattern RAW_JSON_ARRAY_FIELD = Pattern.compile("(?s).*\\[\\s*\\{\\s*\"[^\"]+\"\\s*:.*");
    private static final Pattern KEY_VALUE_PAIR = Pattern.compile("\\b[A-Za-z][A-Za-z0-9_.-]{2,}\\s*[=:]\\s*[^\\s,;]+");
    private static final Pattern GENERATED_IDENTIFIER = Pattern.compile(
            "(?i)\\b(?:finding|agg|run|pkg|cert|case|issue|of|org|ovr)-[a-z0-9][a-z0-9_-]*\\b");
    private static final List<String> FORBIDDEN_FRAGMENTS = List.of(
            "threshold_failed",
            "core official sealed evidence metric",
            "required prompt evidence is missing",
            "finding-eir",
            "agg-source",
            "run-eir-source",
            "pkg-source",
            "cert-source",
            "case-source",
            "issue-eir");

    private PromptQualityCustomerSentencePolicy() {
    }

    public static String requireCustomerSentence(String fieldName, String value) {
        List<String> violations = violations(fieldName, value);
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("Customer-facing sentence quality contract violation: " + String.join("; ", violations));
        }
        return value.trim();
    }

    public static List<String> requireCustomerSentences(String fieldName, Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        int index = 0;
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                result.add(requireCustomerSentence(fieldName + "[" + index + "]", value));
            }
            index++;
        }
        return List.copyOf(result);
    }

    public static boolean isCustomerSentence(String value) {
        return violations("value", value).isEmpty();
    }

    public static List<String> violations(String fieldName, String value) {
        String field = StringUtils.hasText(fieldName) ? fieldName.trim() : "customerSentence";
        List<String> violations = new ArrayList<>();
        if (!StringUtils.hasText(value)) {
            violations.add(field + " is blank.");
            return violations;
        }
        String text = value.trim();
        if (text.length() > MAX_CUSTOMER_SENTENCE_LENGTH) {
            violations.add(field + " exceeds " + MAX_CUSTOMER_SENTENCE_LENGTH + " characters.");
        }
        if (OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            violations.add(field + " contains broken or incorrectly decoded text.");
        }
        if (containsForbiddenInternalText(text)) {
            violations.add(field + " exposes an internal state code or generated identifier.");
        }
        if (containsRawJson(text)) {
            violations.add(field + " exposes raw JSON.");
        }
        if (containsKeyValueDump(text)) {
            violations.add(field + " is stored as a key-value dump.");
        }
        return List.copyOf(violations);
    }

    private static boolean containsForbiddenInternalText(String value) {
        if (OfficialPromptQualityNarrativeCatalog.containsInternalOnlyText(value)) {
            return true;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        for (String token : FORBIDDEN_FRAGMENTS) {
            if (lower.contains(token)) {
                return true;
            }
        }
        return GENERATED_IDENTIFIER.matcher(value).find();
    }

    private static boolean containsRawJson(String value) {
        String trimmed = value.trim();
        return RAW_JSON_FIELD.matcher(trimmed).matches()
                || RAW_JSON_ARRAY_FIELD.matcher(trimmed).matches()
                || (trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]") && trimmed.contains("\""));
    }

    private static boolean containsKeyValueDump(String value) {
        Matcher matcher = KEY_VALUE_PAIR.matcher(value);
        int count = 0;
        while (matcher.find()) {
            count++;
            if (count >= 3) {
                return true;
            }
        }
        return false;
    }

}
