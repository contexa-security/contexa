package io.contexa.contexacore.std.pipeline.step;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.ai.converter.ListOutputConverter;
import org.springframework.ai.converter.MapOutputConverter;
import org.springframework.ai.converter.StructuredOutputConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.support.DefaultConversionService;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class ResponseParsingStep implements PipelineStep {

    private static final Pattern EXPLICIT_ACTION_PATTERN = Pattern.compile(
            "(?is)(?:\\\"action\\\"\\s*:\\s*\\\"|\\\"decision\\\"\\s*:\\s*\\\"|\\bfinal\\s+decision\\b\\s*[:=-]?\\s*|\\brecommended\\s+action\\b\\s*[:=-]?\\s*|\\baction\\b\\s*[:=-]\\s*|\\bdecision\\b\\s*[:=-]\\s*)([`\"'*\\s]*)(ALLOW|CHALLENGE|BLOCK|ESCALATE|DENY|DENIED|REJECT|REJECTED|REVIEW)\\b");
    private static final Pattern EXPLICIT_CONFIDENCE_PATTERN = Pattern.compile(
            "(?is)(?:\\\"confidence\\\"\\s*:\\s*|\\bconfidence\\b\\s*[:=-]\\s*)([0-9]+(?:\\.[0-9]+)?)");
    private static final Pattern EXPLICIT_RISK_PATTERN = Pattern.compile(
            "(?is)(?:\\\"riskScore\\\"\\s*:\\s*|\\brisk\\s*score\\b\\s*[:=-]\\s*)([0-9]+(?:\\.[0-9]+)?)");
    private static final Pattern EXPLICIT_CONFIDENCE_LABEL_PATTERN = Pattern.compile(
            "(?is)(?:\\\"confidence\\\"\\s*:\\s*\\\"|\\bconfidence\\b\\s*[:=-]\\s*)(LOW|MODERATE|MEDIUM|HIGH|VERY_HIGH|CRITICAL)\\b");
    private static final Pattern EXPLICIT_RISK_LABEL_PATTERN = Pattern.compile(
            "(?is)(?:\\\"riskScore\\\"\\s*:\\s*\\\"|\\brisk\\s*score\\b\\s*[:=-]\\s*)(LOW|MODERATE|MEDIUM|HIGH|VERY_HIGH|CRITICAL)\\b");
    private static final Pattern EXPLICIT_REASONING_JSON_PATTERN = Pattern.compile(
            "(?is)\\\"reasoning\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern EXPLICIT_REASONING_TEXT_PATTERN = Pattern.compile(
            "(?im)^\\s*reasoning\\s*[:=-]\\s*(.+)$");
    private static final Pattern EXPLICIT_MITRE_JSON_PATTERN = Pattern.compile(
            "(?is)\\\"mitre\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern EXPLICIT_MITRE_TEXT_PATTERN = Pattern.compile(
            "(?is)(?:\\bmitre\\b\\s*[:=-]\\s*)([A-Z0-9_.-]+)");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DefaultConversionService conversionService = new DefaultConversionService();

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            String finalResponse = context.getStepResult(PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION, String.class);
            if (finalResponse != null) {
                SoarResponse soarResponse = new SoarResponse();
                soarResponse.setAnalysisResult(finalResponse);
                context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, soarResponse);
                return soarResponse;
            }

            Boolean structuredComplete = context.getMetadata("structuredOutputComplete", Boolean.class);
            if (Boolean.TRUE.equals(structuredComplete)) {
                Object structuredResponse = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, Object.class);
                context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, structuredResponse);
                context.addMetadata("parsingComplete", true);
                context.addMetadata("responseType", structuredResponse != null ? structuredResponse.getClass().getSimpleName() : "unknown");
                return structuredResponse;
            }

            Object targetTypeInfo = determineTargetType(request, context);
            String llmResponse = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, String.class);
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                log.error("[{}] LLM response is empty", getStepName());
                return createFallbackResponse(request, context, targetTypeInfo);
            }

            Class<?> decisionTarget = resolveSecurityDecisionTargetClass(targetTypeInfo);
            if (decisionTarget != null) {
                SecurityDecisionResponseLite directDecision = parseSecurityDecisionLite(llmResponse);
                if (directDecision != null) {
                    Object decisionResult = toRequestedSecurityDecisionResponse(directDecision, decisionTarget);
                    context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, decisionResult);
                    enrichWithMetadata(decisionResult, request, context);
                    context.addMetadata("parsingComplete", true);
                    context.addMetadata("securityDecisionDirectParsingApplied", true);
                    context.addMetadata("parsedResponseType", decisionResult.getClass());
                    context.addMetadata("responseType", decisionResult.getClass().getSimpleName());
                    return decisionResult;
                }
            }

            Object result = convertWithSpringAI(llmResponse, targetTypeInfo, context);
            result = coerceTargetResponse(result, llmResponse, targetTypeInfo, context);

            context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, result);
            enrichWithMetadata(result, request, context);
            context.addMetadata("parsingComplete", true);
            context.addMetadata("parsedResponseType", result != null ? result.getClass() : null);
            context.addMetadata("responseType", result != null ? result.getClass().getSimpleName() : "unknown");
            return result;
        });
    }

    private Object convertWithSpringAI(String response, Object targetTypeInfo, PipelineExecutionContext context) {
        try {
            String cleanJson = extractJson(response);

            switch (targetTypeInfo) {
                case Class<?> targetClass -> {
                    if (Map.class.isAssignableFrom(targetClass)) {
                        MapOutputConverter converter = new MapOutputConverter();
                        return converter.convert(cleanJson);
                    } else if (List.class.isAssignableFrom(targetClass)) {
                        ListOutputConverter converter = new ListOutputConverter(conversionService);
                        return converter.convert(cleanJson);
                    } else {
                        try {
                            BeanOutputConverter<?> converter = new BeanOutputConverter<>(targetClass);
                            return converter.convert(cleanJson);
                        } catch (Exception beanEx) {
                            log.error("[{}] BeanOutputConverter failed ({}): {}",
                                    getStepName(), targetClass.getSimpleName(), beanEx.getMessage());

                            MapOutputConverter mapConverter = new MapOutputConverter();
                            Map<String, Object> mapResult = mapConverter.convert(cleanJson);
                            log.error("[{}] Converted to Map successfully (Bean conversion failed)", getStepName());
                            return mapResult;
                        }
                    }
                }
                case ParameterizedTypeReference<?> typeRef -> {
                    BeanOutputConverter<?> converter = new BeanOutputConverter<>(typeRef);
                    return converter.convert(cleanJson);
                }
                case StructuredOutputConverter<?> converter -> {
                    return converter.convert(cleanJson);
                }
                case null, default -> {
                    MapOutputConverter converter = new MapOutputConverter();
                    return converter.convert(cleanJson);
                }
            }
        } catch (Exception e) {
            log.error("[{}] Spring AI conversion failed: {}", getStepName(), e.getMessage());
            log.error("[{}] Detailed error: ", getStepName(), e);

            try {
                String fallbackJson = extractJson(response);
                log.error("[{}] Fallback: Returning JSON string as-is (conversion failed)", getStepName());
                return fallbackJson;
            } catch (Exception fallbackError) {
                log.error("[{}] Final fallback failed: {}", getStepName(), fallbackError.getMessage());
                return response;
            }
        }
    }

    private Object coerceTargetResponse(Object result, String llmResponse, Object targetTypeInfo, PipelineExecutionContext context) {
        Class<?> decisionTarget = resolveSecurityDecisionTargetClass(targetTypeInfo);
        if (decisionTarget == null) {
            return result;
        }

        SecurityDecisionResponseLite lite = toSecurityDecisionLite(result, llmResponse);
        if (lite == null || normalizeAction(lite.getAction()) == null) {
            context.addMetadata("securityDecisionParsingFallbackApplied", true);
            lite = buildFallbackSecurityDecisionLite(llmResponse);
        }

        return toRequestedSecurityDecisionResponse(lite, decisionTarget);
    }

    private Class<?> resolveSecurityDecisionTargetClass(Object targetTypeInfo) {
        if (!(targetTypeInfo instanceof Class<?> targetClass)) {
            return null;
        }
        if (SecurityDecisionResponse.class.isAssignableFrom(targetClass)
                || SecurityDecisionResponseLite.class.isAssignableFrom(targetClass)) {
            return targetClass;
        }
        return null;
    }

    private Object toRequestedSecurityDecisionResponse(SecurityDecisionResponseLite lite, Class<?> targetClass) {
        if (SecurityDecisionResponse.class.equals(targetClass)) {
            return SecurityDecisionResponse.fromLite(lite);
        }
        return lite;
    }

    private SecurityDecisionResponseLite toSecurityDecisionLite(Object candidate, String originalResponse) {
        if (candidate instanceof SecurityDecisionResponse fullResponse) {
            SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
            lite.setRiskScore(fullResponse.getRiskScore());
            lite.setConfidence(fullResponse.getConfidence());
            lite.setAction(fullResponse.getAction());
            lite.setReasoning(fullResponse.getReasoning());
            lite.setMitre(fullResponse.getMitre());
            return normalizeSecurityDecisionLite(lite, originalResponse);
        }
        if (candidate instanceof SecurityDecisionResponseLite liteResponse) {
            return normalizeSecurityDecisionLite(liteResponse, originalResponse);
        }
        if (candidate instanceof Map<?, ?> mapCandidate) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> stringKeyMap = (Map<String, Object>) mapCandidate;
                SecurityDecisionResponseLite lite = securityDecisionLiteFromMap(stringKeyMap);
                return normalizeSecurityDecisionLite(lite, originalResponse);
            } catch (IllegalArgumentException ignored) {
                // fall through to text parsing
            }
        }
        if (candidate instanceof String textCandidate) {
            SecurityDecisionResponseLite parsed = parseSecurityDecisionLite(textCandidate);
            if (parsed != null) {
                return parsed;
            }
        }
        return parseSecurityDecisionLite(originalResponse);
    }

    private SecurityDecisionResponseLite parseSecurityDecisionLite(String response) {
        if (response == null || response.trim().isEmpty()) {
            return null;
        }

        try {
            String cleanJson = extractJson(response);
            if (cleanJson != null && cleanJson.trim().startsWith("{")) {
                SecurityDecisionResponseLite lite = securityDecisionLiteFromMap(
                        objectMapper.readValue(cleanJson, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                        }));
                SecurityDecisionResponseLite normalized = normalizeSecurityDecisionLite(lite, response);
                if (normalized != null && normalizeAction(normalized.getAction()) != null) {
                    return normalized;
                }
            }
        } catch (Exception ignored) {
            // fall through to best-effort parsing
        }

        String normalizedText = normalizeHumanText(response);
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction(extractExplicitAction(normalizedText));
        lite.setConfidence(extractExplicitDouble(EXPLICIT_CONFIDENCE_PATTERN, normalizedText));
        if (lite.getConfidence() == null) {
            lite.setConfidence(extractExplicitScoreLabel(EXPLICIT_CONFIDENCE_LABEL_PATTERN, normalizedText));
        }
        lite.setRiskScore(extractExplicitDouble(EXPLICIT_RISK_PATTERN, normalizedText));
        if (lite.getRiskScore() == null) {
            lite.setRiskScore(extractExplicitScoreLabel(EXPLICIT_RISK_LABEL_PATTERN, normalizedText));
        }
        lite.setMitre(extractExplicitText(EXPLICIT_MITRE_JSON_PATTERN, normalizedText));
        if (lite.getMitre() == null) {
            lite.setMitre(extractExplicitText(EXPLICIT_MITRE_TEXT_PATTERN, normalizedText));
        }
        lite.setReasoning(extractReasoning(normalizedText));
        return normalizeSecurityDecisionLite(lite, response);
    }

    private SecurityDecisionResponseLite normalizeSecurityDecisionLite(SecurityDecisionResponseLite lite, String originalResponse) {
        if (lite == null) {
            return null;
        }

        SecurityDecisionResponseLite normalized = new SecurityDecisionResponseLite();
        normalized.setRiskScore(lite.getRiskScore());
        normalized.setConfidence(lite.getConfidence());
        normalized.setAction(normalizeAction(lite.getAction()));
        normalized.setMitre(normalizeMitre(lite.getMitre()));

        String reasoning = lite.getReasoning();
        if ((reasoning == null || reasoning.isBlank()) && originalResponse != null && !originalResponse.isBlank()) {
            reasoning = extractReasoning(normalizeHumanText(originalResponse));
        }
        normalized.setReasoning(trimReasoning(reasoning));

        if (normalized.getRiskScore() == null
                && normalized.getConfidence() == null
                && normalized.getAction() == null
                && normalized.getMitre() == null
                && (normalized.getReasoning() == null || normalized.getReasoning().isBlank())) {
            return null;
        }

        return normalized;
    }

    private SecurityDecisionResponseLite buildFallbackSecurityDecisionLite(String response) {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("BLOCK");
        lite.setMitre("UNKNOWN");
        String reasoning = extractReasoning(normalizeHumanText(response));
        if (reasoning == null || reasoning.isBlank()) {
            reasoning = "[AI Native] Structured decision response parsing fallback applied";
        }
        lite.setReasoning(trimReasoning(reasoning));
        return lite;
    }

    private String normalizeAction(String action) {
        if (action == null || action.isBlank()) {
            return null;
        }
        String normalized = action.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ALLOW", "CHALLENGE", "BLOCK", "ESCALATE" -> normalized;
            case "DENY", "DENIED", "REJECT", "REJECTED" -> "BLOCK";
            case "REVIEW" -> "ESCALATE";
            default -> null;
        };
    }

    private String normalizeMitre(String mitre) {
        if (mitre == null || mitre.isBlank()) {
            return null;
        }
        return mitre.trim();
    }

    private String extractExplicitAction(String text) {
        Matcher matcher = EXPLICIT_ACTION_PATTERN.matcher(text);
        if (matcher.find()) {
            return normalizeAction(matcher.group(2));
        }
        return null;
    }

    private Double extractExplicitDouble(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            try {
                return Double.parseDouble(matcher.group(1));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Double extractExplicitScoreLabel(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return normalizeScoreLabel(matcher.group(1));
        }
        return null;
    }

    private String extractExplicitText(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                String value = matcher.group(i);
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            }
        }
        return null;
    }

    private String extractReasoning(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String reasoning = extractExplicitText(EXPLICIT_REASONING_JSON_PATTERN, text);
        if (reasoning == null) {
            reasoning = extractExplicitText(EXPLICIT_REASONING_TEXT_PATTERN, text);
        }
        if (reasoning != null && !reasoning.isBlank()) {
            return trimReasoning(reasoning);
        }
        String cleaned = normalizeHumanText(text);
        if (cleaned.isBlank()) {
            return null;
        }
        if ((cleaned.startsWith("{") && cleaned.endsWith("}"))
                || (cleaned.startsWith("[") && cleaned.endsWith("]"))) {
            return null;
        }
        return trimReasoning(cleaned);
    }

    private String trimReasoning(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return null;
        }
        String normalized = normalizeHumanText(reasoning);
        if (normalized.length() <= 280) {
            return normalized;
        }
        return normalized.substring(0, 280).trim();
    }

    private String normalizeHumanText(String response) {
        if (response == null) {
            return "";
        }
        String cleaned = response
                .replace("```json", " ")
                .replace("```", " ")
                .replace("**", " ")
                .replace("__", " ")
                .replace("`", " ")
                .replaceAll("(?m)^\\s*[#>*-]+\\s*", "")
                .replaceAll("\\s+", " ")
                .trim();
        return cleaned;
    }

    private SecurityDecisionResponseLite securityDecisionLiteFromMap(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            return null;
        }
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction(extractActionFromMap(payload));
        lite.setConfidence(extractScoreFromMap(payload, "confidence", "confidenceScore", "decisionConfidence"));
        lite.setRiskScore(extractScoreFromMap(payload, "riskScore", "risk", "risk_score"));
        lite.setReasoning(extractTextFromMap(payload, "reasoning", "analysis", "summary", "decisionReasoning"));
        lite.setMitre(extractTextFromMap(payload, "mitre", "mitreAttack", "mitre_attack", "mitreTechnique"));
        return lite;
    }

    private String extractActionFromMap(Map<String, Object> payload) {
        String direct = extractTextFromMap(payload, "action", "decision", "recommendedAction", "finalDecision");
        return normalizeAction(direct);
    }

    private Double extractScoreFromMap(Map<String, Object> payload, String... keys) {
        for (String key : keys) {
            Double parsed = coerceScore(payload.get(key));
            if (parsed != null) {
                return parsed;
            }
        }
        return null;
    }

    private String extractTextFromMap(Map<String, Object> payload, String... keys) {
        for (String key : keys) {
            Object value = payload.get(key);
            if (value instanceof String text && !text.isBlank()) {
                return text.trim();
            }
        }
        return null;
    }

    private Double coerceScore(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return normalizeNumericScore(number.doubleValue());
        }
        if (value instanceof String text) {
            String normalized = text.trim();
            if (normalized.isEmpty()) {
                return null;
            }
            try {
                return normalizeNumericScore(Double.parseDouble(normalized));
            } catch (NumberFormatException ignored) {
                return normalizeScoreLabel(normalized);
            }
        }
        return null;
    }

    private Double normalizeNumericScore(Double score) {
        if (score == null || !Double.isFinite(score)) {
            return null;
        }
        return Math.max(0.0d, Math.min(1.0d, score));
    }

    private Double normalizeScoreLabel(String label) {
        if (label == null || label.isBlank()) {
            return null;
        }
        String normalized = label.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        return switch (normalized) {
            case "LOW" -> 0.54d;
            case "MODERATE", "MEDIUM" -> 0.74d;
            case "HIGH" -> 0.85d;
            case "VERY_HIGH", "CRITICAL" -> 0.95d;
            default -> null;
        };
    }

    private String extractJson(String response) {
        if (response == null || response.trim().isEmpty()) {
            return "{}";
        }

        String cleaned = response.trim();

        if (cleaned.contains("```json")) {
            int start = cleaned.indexOf("```json") + 7;
            int end = cleaned.indexOf("```", start);
            if (end > start) {
                cleaned = cleaned.substring(start, end).trim();
            }
        } else if (cleaned.contains("```")) {
            int start = cleaned.indexOf("```") + 3;
            int end = cleaned.indexOf("```", start);
            if (end > start) {
                String content = cleaned.substring(start, end).trim();
                int firstNewline = content.indexOf('\n');
                if (firstNewline > 0 && firstNewline < 20) {
                    String firstLine = content.substring(0, firstNewline).trim();
                    if (firstLine.matches("^[a-zA-Z]+$")) {
                        content = content.substring(firstNewline + 1).trim();
                    }
                }
                cleaned = content;
            }
        }

        if (cleaned.isEmpty()) {
            return "{}";
        }

        if (cleaned.startsWith("{") || cleaned.startsWith("[")) {
            try {
                objectMapper.readTree(cleaned);
                return cleaned;
            } catch (Exception e) {
                try {
                    String fixed = cleaned.replaceAll(",\\s*([}\\]])", "$1");
                    objectMapper.readTree(fixed);
                    return fixed;
                } catch (Exception retryError) {
                    log.error("[{}] Invalid JSON structure: {}", getStepName(), e.getMessage());
                }
            }
        }

        int jsonObjStart = cleaned.indexOf('{');
        int jsonArrStart = cleaned.indexOf('[');
        if (jsonObjStart >= 0 || jsonArrStart >= 0) {
            int startIdx = (jsonObjStart >= 0 && (jsonArrStart < 0 || jsonObjStart < jsonArrStart))
                    ? jsonObjStart : jsonArrStart;
            char closeChar = (cleaned.charAt(startIdx) == '{') ? '}' : ']';
            int lastClose = cleaned.lastIndexOf(closeChar);
            if (lastClose > startIdx) {
                String candidate = cleaned.substring(startIdx, lastClose + 1);
                try {
                    objectMapper.readTree(candidate);
                    return candidate;
                } catch (Exception e) {
                    try {
                        String fixed = candidate.replaceAll(",\\s*([}\\]])", "$1");
                        objectMapper.readTree(fixed);
                        return fixed;
                    } catch (Exception ignored) {
                        log.error("[{}] Failed to extract JSON from mixed content", getStepName());
                    }
                }
            }
        }

        return response;
    }

    private Object determineTargetType(AIRequest<?> request, PipelineExecutionContext context) {
        Class<?> aiGenerationType = context.getMetadata("aiGenerationType", Class.class);
        if (aiGenerationType != null) {
            return aiGenerationType;
        }

        Object typeFromContext = context.getMetadata("targetResponseType", Object.class);
        if (typeFromContext != null) {
            return typeFromContext;
        }

        Object typeFromRequest = request.getParameter("responseType", Object.class);
        if (typeFromRequest != null) {
            return typeFromRequest;
        }

        Object converter = request.getParameter("outputConverter", Object.class);
        if (converter instanceof StructuredOutputConverter) {
            return converter;
        }

        return Map.class;
    }

    private void enrichWithMetadata(Object response, AIRequest<?> request, PipelineExecutionContext context) {
        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("executionTimeMs", executionTime);
        }

        context.addMetadata("status", response != null ? "SUCCESS" : "FAILURE");
        context.addMetadata("completedAt", System.currentTimeMillis());

        if (response != null) {
            context.addMetadata("responseClass", response.getClass().getName());
        }
    }

    private Object createFallbackResponse(AIRequest<?> request, PipelineExecutionContext context, Object targetTypeInfo) {
        log.error("[{}] Creating fallback response", getStepName());
        Class<?> decisionTarget = resolveSecurityDecisionTargetClass(targetTypeInfo);
        if (decisionTarget != null) {
            Object fallback = toRequestedSecurityDecisionResponse(
                    buildFallbackSecurityDecisionLite("[AI Native] No response from LLM"),
                    decisionTarget);
            enrichWithMetadata(fallback, request, context);
            context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, fallback);
            return fallback;
        }

        DefaultAIResponse fallback = new DefaultAIResponse(Map.of("error", "No response from LLM", "status", "fallback"));
        enrichWithMetadata(fallback, request, context);
        context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, fallback);
        return fallback;
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.RESPONSE_PARSING;
    }

    @Override
    public int getOrder() {
        return 5;
    }
}

