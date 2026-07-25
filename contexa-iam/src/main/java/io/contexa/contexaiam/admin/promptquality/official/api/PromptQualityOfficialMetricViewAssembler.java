package io.contexa.contexaiam.admin.promptquality.official.api;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Builds the metric-family and reverification portions of the official console view. */
final class PromptQualityOfficialMetricViewAssembler {

    private static final Set<String> PROMPT_OFFICIAL_METRIC_CODES = Set.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR", "RAP", "RPI", "BMA", "USNS", "BSR", "PRE");
    private static final Set<String> LLM_DECISION_METRIC_CODES = Set.of(
            "D01", "D02", "D03", "D04", "D05");

    private final MessageSource messages;

    PromptQualityOfficialMetricViewAssembler(MessageSource messages) {
        this.messages = Objects.requireNonNull(messages, "messages");
    }

    Map<String, Object> metricFamilyPayload(OfficialRunPackageDetail detail, String family) {
        List<OfficialVerificationMetricTrace> runs = detail.runs().stream()
                .filter(run -> family.equals(metricFamily(run)))
                .toList();
        Set<String> executedMetricCodes = new LinkedHashSet<>();
        for (OfficialVerificationMetricTrace run : runs) {
            String code = normalizeMetricCode(run.metricCode());
            if (StringUtils.hasText(code)) {
                executedMetricCodes.add(code);
            }
        }
        List<Map<String, Object>> expectedMetrics = expectedMetricCodes(family).stream()
                .map(code -> expectedMetricPayload(code, executedMetricCodes.contains(code)))
                .toList();
        long notAppliedCount = expectedMetrics.stream()
                .filter(metric -> Boolean.FALSE.equals(metric.get("executed")))
                .count();

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", detail.packageId());
        payload.put("aggregateRunId", detail.aggregateRunId());
        payload.put("family", family);
        payload.put("label", metricFamilyLabel(family));
        payload.put("expectedMetricCount", expectedMetrics.size());
        payload.put("executedMetricCount", runs.size());
        payload.put("notAppliedMetricCount", notAppliedCount);
        payload.put("expectedMetrics", expectedMetrics);
        payload.put("totalRunCount", runs.size());
        payload.put("passedRunCount", (int) runs.stream().filter(run -> passState(run.state())).count());
        payload.put("failedRunCount", (int) runs.stream().filter(run -> !passState(run.state())).count());
        payload.put("runs", runs);
        payload.put("failureCauses", detail.failureCauses().stream()
                .filter(failure -> runs.stream().anyMatch(run ->
                        normalizeMetricCode(run.metricCode()).equals(normalizeMetricCode(failure.metricCode()))))
                .toList());
        return payload;
    }

    List<String> expectedMetricCodes(String family) {
        if ("prompt".equals(family)) {
            return PROMPT_OFFICIAL_METRIC_CODES.stream().sorted().toList();
        }
        if ("decision".equals(family)) {
            return LLM_DECISION_METRIC_CODES.stream().sorted().toList();
        }
        return List.of();
    }

    Map<String, Object> expectedMetricPayload(String metricCode, boolean executed) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("metricCode", metricCode);
        item.put("label", expectedMetricLabel(metricCode));
        item.put("executed", executed);
        item.put("status", executed ? "EXECUTED" : "NOT_APPLIED_TO_THIS_EVIDENCE");
        item.put("description", messages.resolve(executed
                ? "enterprise.pqa.official.metric.description.executed"
                : "enterprise.pqa.official.metric.description.notExecuted"));
        return item;
    }

    String expectedMetricLabel(String metricCode) {
        String normalized = normalizeMetricCode(metricCode);
        if (!PROMPT_OFFICIAL_METRIC_CODES.contains(normalized)
                && !LLM_DECISION_METRIC_CODES.contains(normalized)) {
            return metricCode;
        }
        return messages.resolve("enterprise.pqa.official.metric." + normalized.toLowerCase(Locale.ROOT) + ".label");
    }

    Map<String, Object> reverifyOptionsPayload(OfficialRunPackageDetail detail, String endpoint) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", detail.packageId());
        payload.put("aggregateRunId", detail.aggregateRunId());
        payload.put("prompt", reverifyOption(detail, "prompt", endpoint));
        payload.put("decision", reverifyOption(detail, "decision", endpoint));
        payload.put("full", reverifyOption(detail, "full", endpoint));
        return payload;
    }

    private Map<String, Object> reverifyOption(
            OfficialRunPackageDetail detail,
            String scope,
            String endpoint) {
        List<OfficialVerificationMetricTrace> scopedRuns = "full".equals(scope)
                ? detail.runs()
                : detail.runs().stream().filter(run -> scope.equals(metricFamily(run))).toList();
        Map<String, Object> option = new LinkedHashMap<>();
        option.put("scope", scope);
        option.put("label", switch (scope) {
            case "prompt" -> messages.resolve("enterprise.pqa.official.reverify.prompt");
            case "decision" -> messages.resolve("enterprise.pqa.official.reverify.decision");
            default -> messages.resolve("enterprise.pqa.official.reverify.full");
        });
        option.put("totalRunCount", scopedRuns.size());
        option.put("passedRunCount", (int) scopedRuns.stream().filter(run -> passState(run.state())).count());
        option.put("failedRunCount", (int) scopedRuns.stream().filter(run -> !passState(run.state())).count());
        option.put("endpoint", endpoint);
        return option;
    }

    String metricFamily(OfficialVerificationMetricTrace run) {
        String code = normalizeMetricCode(run == null ? null : run.metricCode());
        String group = normalizeMetricCode(run == null ? null : run.groupName());
        if (LLM_DECISION_METRIC_CODES.contains(code)
                || "LLM_DECISION".equals(group)
                || "DECISION_OFFICIAL".equals(group)) {
            return "decision";
        }
        if (PROMPT_OFFICIAL_METRIC_CODES.contains(code)
                || Set.of("IMPLEMENTATION_ALIGNMENT", "RAG_AND_BASELINE", "BEHAVIORAL_CONTEXT", "RESOURCE_ELIGIBILITY").contains(group)) {
            return "prompt";
        }
        return "other";
    }

    String metricFamilyLabel(String family) {
        return switch (family) {
            case "prompt" -> messages.resolve("enterprise.pqa.official.family.prompt");
            case "decision" -> messages.resolve("enterprise.pqa.official.family.decision");
            default -> messages.resolve("enterprise.pqa.official.family.other");
        };
    }

    String normalizeMetricCode(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private boolean passState(String state) {
        String normalized = state == null ? "" : state.toUpperCase(Locale.ROOT);
        return normalized.equals("PASSED") || normalized.equals("PASS") || normalized.equals("SUCCESS");
    }

    @FunctionalInterface
    interface MessageSource {
        String resolve(String key, Object... args);
    }
}
