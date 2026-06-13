package io.contexa.contexacore.verification.runtime;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class OfficialVerificationMetricRuntimeProfileSupport {

    public static final String ATTR_RUNTIME_PROFILE_CODE = "officialVerification.runtimeProfileCode";
    public static final String ATTR_RUNTIME_MODEL_ID = "officialVerification.runtimeModelId";
    public static final String ATTR_RUNTIME_TEMPERATURE = "officialVerification.runtimeTemperature";
    public static final String ATTR_RUNTIME_TOP_P = "officialVerification.runtimeTopP";
    public static final String ATTR_RUNTIME_SEED = "officialVerification.runtimeSeed";
    public static final String ATTR_RUNTIME_MAX_TOKENS = "officialVerification.runtimeMaxTokens";
    public static final String ATTR_RUNTIME_DISABLE_RETRIES = "officialVerification.runtimeDisableRetries";
    public static final String ATTR_RUNTIME_DISABLE_OLLAMA_THINKING = "officialVerification.runtimeDisableOllamaThinking";
    public static final String ATTR_RUNTIME_COMPARISON_MODELS = "officialVerification.runtimeComparisonModels";

    private static final String MODEL_ID_HEADER = "X-Contexa-Official-Verification-Model-Id";
    private static final String TEMPERATURE_HEADER = "X-Contexa-Official-Verification-Temperature";
    private static final String TOP_P_HEADER = "X-Contexa-Official-Verification-Top-P";
    private static final String SEED_HEADER = "X-Contexa-Official-Verification-Seed";
    private static final String MAX_TOKENS_HEADER = "X-Contexa-Official-Verification-Max-Tokens";
    private static final String DISABLE_RETRIES_HEADER = "X-Contexa-Official-Verification-Disable-Retries";
    private static final String DISABLE_OLLAMA_THINKING_HEADER = "X-Contexa-Official-Verification-Disable-Ollama-Thinking";

    public static final String PROFILE_CONTEXT_FAST = "context-fast";
    public static final String PROFILE_DECISION_STRONG = "decision-strong";
    public static final String PROFILE_CUSTOM = "custom";

    public static final String DEFAULT_CONTEXT_MODEL = "qwen2.5:7b";
    public static final String DEFAULT_DECISION_MODEL = "qwen3.1:8b";

    private static final Set<String> DECISION_METRICS = Set.of("CDC", "ERA", "SUHR");

    private OfficialVerificationMetricRuntimeProfileSupport() {
    }

    public static boolean isDecisionMetric(String metricCode) {
        return DECISION_METRICS.contains(normalizeMetricCode(metricCode));
    }

    public static RuntimeSelection resolve(
            String metricCode,
            String requestedProfileCode,
            String requestedModelId,
            List<String> comparisonModelIds,
            Double requestedTemperature,
            Double requestedTopP,
            Integer requestedSeed,
            Integer requestedMaxTokens,
            Boolean requestedDisableRetries,
            Boolean requestedDisableOllamaThinking
    ) {
        boolean decisionMetric = isDecisionMetric(metricCode);
        String normalizedProfileCode = normalizeProfileCode(requestedProfileCode, decisionMetric);
        String runtimeModelId = StringUtils.hasText(requestedModelId)
                ? requestedModelId.trim()
                : defaultModelId(normalizedProfileCode, decisionMetric);
        Double temperature = requestedTemperature != null ? requestedTemperature : 0.0d;
        Double topP = requestedTopP != null ? requestedTopP : 0.2d;
        Integer seed = requestedSeed != null ? requestedSeed : 7;
        Integer maxTokens = requestedMaxTokens != null
                ? Math.max(32, requestedMaxTokens)
                : (decisionMetric ? 96 : 64);
        boolean disableRetries = requestedDisableRetries == null || requestedDisableRetries;
        boolean disableOllamaThinking = requestedDisableOllamaThinking == null || requestedDisableOllamaThinking;
        List<String> normalizedComparisons = normalizeModelList(comparisonModelIds, runtimeModelId);
        return new RuntimeSelection(
                normalizeMetricCode(metricCode),
                normalizedProfileCode,
                runtimeModelId,
                temperature,
                topP,
                seed,
                maxTokens,
                disableRetries,
                disableOllamaThinking,
                normalizedComparisons
        );
    }

    public static void recordRequestAttributes(HttpServletRequest request, RuntimeSelection selection) {
        if (request == null || selection == null) {
            return;
        }
        request.setAttribute(ATTR_RUNTIME_PROFILE_CODE, selection.profileCode());
        request.setAttribute(ATTR_RUNTIME_MODEL_ID, selection.modelId());
        request.setAttribute(ATTR_RUNTIME_TEMPERATURE, selection.temperature());
        request.setAttribute(ATTR_RUNTIME_TOP_P, selection.topP());
        request.setAttribute(ATTR_RUNTIME_SEED, selection.seed());
        request.setAttribute(ATTR_RUNTIME_MAX_TOKENS, selection.maxTokens());
        request.setAttribute(ATTR_RUNTIME_DISABLE_RETRIES, selection.disableRetries());
        request.setAttribute(ATTR_RUNTIME_DISABLE_OLLAMA_THINKING, selection.disableOllamaThinking());
        request.setAttribute(
                ATTR_RUNTIME_COMPARISON_MODELS,
                selection.comparisonModelIds().isEmpty() ? null : String.join(", ", selection.comparisonModelIds())
        );
    }

    public static void applyHeaders(HttpHeaders headers, HttpServletRequest request) {
        if (headers == null || request == null) {
            return;
        }
        setHeader(headers, MODEL_ID_HEADER, request.getAttribute(ATTR_RUNTIME_MODEL_ID));
        setHeader(headers, TEMPERATURE_HEADER, request.getAttribute(ATTR_RUNTIME_TEMPERATURE));
        setHeader(headers, TOP_P_HEADER, request.getAttribute(ATTR_RUNTIME_TOP_P));
        setHeader(headers, SEED_HEADER, request.getAttribute(ATTR_RUNTIME_SEED));
        setHeader(headers, MAX_TOKENS_HEADER, request.getAttribute(ATTR_RUNTIME_MAX_TOKENS));
        setHeader(headers, DISABLE_RETRIES_HEADER, request.getAttribute(ATTR_RUNTIME_DISABLE_RETRIES));
        setHeader(headers, DISABLE_OLLAMA_THINKING_HEADER, request.getAttribute(ATTR_RUNTIME_DISABLE_OLLAMA_THINKING));
    }

    private static String normalizeMetricCode(String metricCode) {
        return StringUtils.hasText(metricCode) ? metricCode.trim().toUpperCase(Locale.ROOT) : "";
    }

    private static String normalizeProfileCode(String requestedProfileCode, boolean decisionMetric) {
        String normalized = StringUtils.hasText(requestedProfileCode)
                ? requestedProfileCode.trim().toLowerCase(Locale.ROOT)
                : "";
        return switch (normalized) {
            case PROFILE_CONTEXT_FAST -> PROFILE_CONTEXT_FAST;
            case PROFILE_DECISION_STRONG -> PROFILE_DECISION_STRONG;
            case PROFILE_CUSTOM -> PROFILE_CUSTOM;
            default -> decisionMetric ? PROFILE_DECISION_STRONG : PROFILE_CONTEXT_FAST;
        };
    }

    private static String defaultModelId(String normalizedProfileCode, boolean decisionMetric) {
        if (PROFILE_CONTEXT_FAST.equals(normalizedProfileCode)) {
            return DEFAULT_CONTEXT_MODEL;
        }
        if (PROFILE_DECISION_STRONG.equals(normalizedProfileCode)) {
            return DEFAULT_DECISION_MODEL;
        }
        return decisionMetric ? DEFAULT_DECISION_MODEL : DEFAULT_CONTEXT_MODEL;
    }

    private static List<String> normalizeModelList(List<String> comparisonModelIds, String primaryModelId) {
        if (comparisonModelIds == null || comparisonModelIds.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        for (String candidate : comparisonModelIds) {
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            String normalized = candidate.trim();
            if (normalized.equalsIgnoreCase(primaryModelId)) {
                continue;
            }
            ordered.add(normalized);
        }
        return ordered.isEmpty() ? List.of() : List.copyOf(new ArrayList<>(ordered));
    }

    private static void setHeader(HttpHeaders headers, String name, Object value) {
        if (headers == null || !StringUtils.hasText(name) || value == null) {
            return;
        }
        String normalized = String.valueOf(value).trim();
        if (normalized.isBlank()) {
            return;
        }
        headers.set(name, normalized);
    }

    public record RuntimeSelection(
            String metricCode,
            String profileCode,
            String modelId,
            Double temperature,
            Double topP,
            Integer seed,
            Integer maxTokens,
            boolean disableRetries,
            boolean disableOllamaThinking,
            List<String> comparisonModelIds
    ) {
    }
}
