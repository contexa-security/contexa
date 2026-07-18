package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class OfficialRuntimeEvidenceCheckInterpreter {

    private final ObjectMapper objectMapper;

    OfficialRuntimeEvidenceCheckInterpreter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    String inputReadinessState(RuntimeEvidenceCheckResult check) {
        return inputNotReady(check)
                ? "INPUT_NOT_READY"
                : firstNonBlank(check == null ? null : check.inputReadinessState(), "READY");
    }

    String purposeResult(RuntimeEvidenceCheckResult check) {
        if (inputNotReady(check)) {
            return "INPUT_NOT_READY";
        }
        String purpose = normalize(check == null ? null : check.purposeResult());
        return switch (purpose) {
            case "PURPOSE_PASSED", "PURPOSE_FAILED", "NOT_APPLICABLE" -> purpose;
            case "PASSED", "PASS", "SUCCESS" -> "PURPOSE_PASSED";
            case "FAILED", "FAIL", "BLOCKED", "THRESHOLD_FAILED" -> "PURPOSE_FAILED";
            case "NOT_EVALUATED_INPUT_NOT_READY", "INPUT_NOT_READY" -> "INPUT_NOT_READY";
            default -> check != null && check.pass() ? "PURPOSE_PASSED" : "PURPOSE_FAILED";
        };
    }

    boolean inputNotReady(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return false;
        }
        String readiness = normalize(check.inputReadinessState());
        String purpose = normalize(check.purposeResult());
        String failure = normalize(check.failureType());
        if ("NOT_READY".equals(readiness) || "INPUT_NOT_READY".equals(readiness)
                || "NOT_EVALUATED_INPUT_NOT_READY".equals(purpose) || "INPUT_NOT_READY".equals(purpose)) {
            return true;
        }
        return "INPUT_NOT_READY".equals(failure) && readinessEvidencePresent(check);
    }

    List<String> detectedSignals(RuntimeEvidenceCheckResult check) {
        List<String> signals = jsonStringList(check == null ? null : check.detectedSignalsJson());
        if (!signals.isEmpty() || !inputNotReady(check)) {
            return signals;
        }
        List<String> extracted = new ArrayList<>();
        extracted.addAll(extract(check.actualValue(), "누락된 항목", "missing:"));
        extracted.addAll(extract(check.actualValue(), "확인된 항목", "present:"));
        extracted.addAll(extract(check.actualValue(), "Missing:", "missing:"));
        extracted.addAll(extract(check.actualValue(), "Present:", "present:"));
        return extracted.stream().filter(StringUtils::hasText).distinct().toList();
    }

    private boolean readinessEvidencePresent(RuntimeEvidenceCheckResult check) {
        if (!jsonStringList(check.detectedSignalsJson()).isEmpty()) {
            return true;
        }
        String text = safe(check.actualValue()) + " " + safe(check.operatorReason());
        String normalized = text.toLowerCase(Locale.ROOT);
        return normalized.contains("missing:")
                || normalized.contains("missing inputs")
                || normalized.contains("누락된 항목");
    }

    private List<String> extract(String value, String marker, String prefix) {
        if (!StringUtils.hasText(value) || !StringUtils.hasText(marker)) {
            return List.of();
        }
        int start = value.indexOf(marker);
        if (start < 0) {
            return List.of();
        }
        int contentStart = start + marker.length();
        int end = value.indexOf('.', contentStart);
        String segment = value.substring(contentStart, end < 0 ? value.length() : end);
        List<String> result = new ArrayList<>();
        for (String part : segment.split(",")) {
            String trimmed = part.trim();
            if (StringUtils.hasText(trimmed) && !"없음".equals(trimmed)) {
                result.add(prefix + trimmed);
            }
        }
        return List.copyOf(result);
    }

    private List<String> jsonStringList(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            for (Object item : raw) {
                if (item == null) {
                    continue;
                }
                String text = item instanceof String string ? string : objectMapper.writeValueAsString(item);
                if (StringUtils.hasText(text)) {
                    result.add(text.trim());
                }
            }
            return List.copyOf(result);
        }
        catch (Exception ignored) {
            return List.of(value.trim());
        }
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
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
