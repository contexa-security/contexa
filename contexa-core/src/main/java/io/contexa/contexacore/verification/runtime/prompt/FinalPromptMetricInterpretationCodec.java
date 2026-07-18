package io.contexa.contexacore.verification.runtime.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

final class FinalPromptMetricInterpretationCodec {

    private static final Pattern STRUCTURED_EVIDENCE_VALUE =
            Pattern.compile("\"evidenceValue\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
    private static final Pattern STRUCTURED_RUNTIME_FACTS =
            Pattern.compile("\"runtimeFacts\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");

    private FinalPromptMetricInterpretationCodec() {
    }

    static String interpretationLinksJson(
            FinalPromptMetricContract metricContract,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            String evidence) {
        return interpretationLinksJson(
                metricContract,
                metricCode,
                checkContract,
                passed ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                evidence);
    }

    static String interpretationLinksJson(
            FinalPromptMetricContract metricContract,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            String purposeResult,
            String evidence) {
        return jsonArray(List.of(jsonObject(
                "metricCode", metricCode,
                "purpose", firstNonBlank(metricContract.purpose(), ""),
                "checkName", firstNonBlank(checkContract.checkName(), ""),
                "source", firstNonBlank(checkContract.source(), ""),
                "issueKey", firstNonBlank(checkContract.issueKey(), ""),
                "purposeResult", firstNonBlank(purposeResult, ""),
                "purposeSignal", firstNonBlank(checkContract.purposeSignal(), ""),
                "meaning", firstNonBlank(checkContract.meaning(), ""),
                "securityRelevance", firstNonBlank(checkContract.securityRelevance(), ""),
                "interpretationLink", firstNonBlank(checkContract.interpretationLink(), ""),
                "evidence", firstNonBlank(interpretationEvidenceText(evidence), ""))));
    }

    static String interpretationEvidenceText(String evidence) {
        if (!StringUtils.hasText(evidence)) {
            return "";
        }
        String text = evidence.trim();
        Matcher matcher = STRUCTURED_EVIDENCE_VALUE.matcher(text);
        if (matcher.find()) {
            return unescapeJsonText(matcher.group(1));
        }
        return text.startsWith("{") && text.endsWith("}") ? "" : text;
    }

    static String interpretationRuntimeFactsText(String evidence) {
        if (!StringUtils.hasText(evidence)) {
            return "";
        }
        Matcher matcher = STRUCTURED_RUNTIME_FACTS.matcher(evidence.trim());
        return matcher.find() ? unescapeJsonText(matcher.group(1)) : "";
    }

    static String readinessInterpretationJson(
            FinalPromptMetricContract metricContract,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            String missingInputs,
            String presentInputs) {
        return jsonArray(List.of(jsonObject(
                "metricCode", metricCode,
                "purpose", firstNonBlank(metricContract.purpose(), ""),
                "checkName", firstNonBlank(checkContract.checkName(), ""),
                "source", firstNonBlank(checkContract.source(), ""),
                "purposeResult", "INPUT_NOT_READY",
                "missingInputs", missingInputs,
                "presentInputs", presentInputs)));
    }

    static String jsonArray(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "[]";
        }
        return "[" + values.stream()
                .filter(StringUtils::hasText)
                .map(value -> value.startsWith("{") && value.endsWith("}") ? value : quoteJson(value))
                .collect(Collectors.joining(",")) + "]";
    }

    static String jsonObject(String... keysAndValues) {
        if (keysAndValues == null || keysAndValues.length == 0) {
            return "{}";
        }
        List<String> pairs = new ArrayList<>();
        for (int index = 0; index + 1 < keysAndValues.length; index += 2) {
            pairs.add(quoteJson(keysAndValues[index]) + ":" + quoteJson(keysAndValues[index + 1]));
        }
        return "{" + String.join(",", pairs) + "}";
    }

    private static String quoteJson(String value) {
        String safe = value == null ? "" : value;
        return "\"" + safe
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private static String unescapeJsonText(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", " ")
                .replace("\\r", " ")
                .replace("\\t", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }
}