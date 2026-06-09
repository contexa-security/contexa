package io.contexa.contexacore.std.pipeline.step;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionOutputParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.ai.converter.ListOutputConverter;
import org.springframework.ai.converter.MapOutputConverter;
import org.springframework.ai.converter.StructuredOutputConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.support.DefaultConversionService;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Slf4j
public class ResponseParsingStep implements PipelineStep {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DefaultConversionService conversionService = new DefaultConversionService();
    private final SecurityDecisionOutputParser securityDecisionOutputParser = new SecurityDecisionOutputParser();

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

            StructuredOutputPolicy structuredOutputPolicy = resolveStructuredOutputPolicy(request, context);
            Boolean structuredComplete = context.getMetadata("structuredOutputComplete", Boolean.class);
            if (Boolean.TRUE.equals(structuredComplete)) {
                Object structuredResponse = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, Object.class);
                context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, structuredResponse);
                context.addMetadata("parsingComplete", true);
                if (!structuredOutputPolicy.allowsRawFallback()) {
                    context.addMetadata("llmDecisionPresent", true);
                    context.addMetadata("securityDecisionParsingFallbackApplied", false);
                    context.addMetadata("syntheticSecurityDecisionApplied", false);
                }
                context.addMetadata("responseType", structuredResponse != null ? structuredResponse.getClass().getSimpleName() : "unknown");
                return structuredResponse;
            }

            Object targetTypeInfo = determineTargetType(request, context);
            Object llmExecutionResult = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, Object.class);
            if (isSecurityDecisionTarget(targetTypeInfo)) {
                Object result = parseSecurityDecisionResult(llmExecutionResult, context);
                context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, result);
                context.addMetadata("parsingComplete", true);
                context.addMetadata("parsedResponseType", result != null ? result.getClass() : null);
                context.addMetadata("responseType", result != null ? result.getClass().getSimpleName() : "unknown");
                enrichWithMetadata(result, request, context);
                return result;
            }

            String llmResponse = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, String.class);
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                log.error("[{}] LLM response is empty", getStepName());
                if (!structuredOutputPolicy.allowsRawFallback()) {
                    context.addMetadata("llmDecisionPresent", false);
                    context.addMetadata("securityDecisionParsingFallbackApplied", false);
                    context.addMetadata("syntheticSecurityDecisionApplied", false);
                    throw new StructuredOutputExecutionException(
                            StructuredOutputFailureCategory.EMPTY_RESPONSE,
                            "Structured response is missing");
                }
                return createFallbackResponse(request, context, targetTypeInfo);
            }

            if (!structuredOutputPolicy.allowsRawFallback()) {
                context.addMetadata("llmDecisionPresent", false);
                context.addMetadata("securityDecisionParsingFallbackApplied", false);
                context.addMetadata("syntheticSecurityDecisionApplied", false);
                StructuredOutputFailureCategory failureCategory = Boolean.TRUE.equals(context.getMetadata("rawExecutionAttempted", Boolean.class))
                        ? StructuredOutputFailureCategory.RAW_EXECUTION_FORBIDDEN
                        : StructuredOutputFailureCategory.STRUCTURED_OUTPUT_MISSING;
                throw new StructuredOutputExecutionException(
                        failureCategory,
                        "Raw parsing is forbidden; structured output is required");
            }

            Object result = convertWithSpringAI(llmResponse, targetTypeInfo, context);
            result = validateStructuredOutputResult(result, targetTypeInfo, structuredOutputPolicy, context);

            context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, result);
            enrichWithMetadata(result, request, context);
            context.addMetadata("parsingComplete", true);
            context.addMetadata("parsedResponseType", result != null ? result.getClass() : null);
            context.addMetadata("responseType", result != null ? result.getClass().getSimpleName() : "unknown");
            return result;
        });
    }

    private Object parseSecurityDecisionResult(Object llmExecutionResult, PipelineExecutionContext context) {
        context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
        if (llmExecutionResult instanceof SecurityDecisionResponseLite lite) {
            context.addMetadata("structuredOutputComplete", true);
            context.addMetadata("llmDecisionPresent", true);
            context.addMetadata("securityDecisionCoreFieldsPresent", true);
            context.addMetadata("securityDecisionParsingFallbackApplied", false);
            context.addMetadata("syntheticSecurityDecisionApplied", false);
            context.addMetadata("securityDecisionOutputRepairApplied", false);
            context.addMetadata("securityDecisionParseFailureCategory", "NONE");
            return lite;
        }
        String rawResponse = llmExecutionResult instanceof String text
                ? text
                : llmExecutionResult != null ? String.valueOf(llmExecutionResult) : "";
        SecurityDecisionResponseLite parsed = securityDecisionOutputParser.parse(rawResponse, context);
        context.addMetadata("structuredOutputComplete", true);
        return parsed;
    }

    private Object convertWithSpringAI(String response, Object targetTypeInfo, PipelineExecutionContext context) {
        try {
            String cleanJson = extractJson(response);

            if (targetTypeInfo instanceof Class<?> targetClass) {
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
            } else if (targetTypeInfo instanceof ParameterizedTypeReference<?> typeRef) {
                BeanOutputConverter<?> converter = new BeanOutputConverter<>(typeRef);
                return converter.convert(cleanJson);
            } else if (targetTypeInfo instanceof StructuredOutputConverter<?> converter) {
                return converter.convert(cleanJson);
            } else {
                MapOutputConverter converter = new MapOutputConverter();
                return converter.convert(cleanJson);
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

    private Object validateStructuredOutputResult(
            Object result,
            Object targetTypeInfo,
            StructuredOutputPolicy structuredOutputPolicy,
            PipelineExecutionContext context) {
        if (structuredOutputPolicy.allowsRawFallback()) {
            return result;
        }
        if (result == null) {
            context.addMetadata("llmDecisionPresent", false);
            throw new StructuredOutputExecutionException(
                    StructuredOutputFailureCategory.VALIDATION_FAILED,
                    "Structured response is null");
        }
        if (targetTypeInfo instanceof Class<?> targetClass && !targetClass.isInstance(result)) {
            context.addMetadata("llmDecisionPresent", false);
            throw new StructuredOutputExecutionException(
                    StructuredOutputFailureCategory.VALIDATION_FAILED,
                    "Structured response did not map to the requested target type: " + targetClass.getName());
        }
        if (result instanceof String) {
            context.addMetadata("llmDecisionPresent", false);
            throw new StructuredOutputExecutionException(
                    StructuredOutputFailureCategory.VALIDATION_FAILED,
                    "Structured response degraded to raw text");
        }
        return result;
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
                    String recovered = recoverTruncatedJson(cleaned);
                    if (recovered != null) {
                        return recovered;
                    }
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
                        String recovered = recoverTruncatedJson(candidate);
                        if (recovered != null) {
                            return recovered;
                        }
                        log.error("[{}] Failed to extract JSON from mixed content", getStepName());
                    }
                }
            }
        }

        return response;
    }

    private String recoverTruncatedJson(String truncated) {
        if (truncated == null || truncated.length() < 2) {
            return null;
        }

        char openChar = truncated.charAt(0);
        char closeChar = (openChar == '{') ? '}' : ']';

        int depth = 0;
        int lastCompleteEntry = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < truncated.length(); i++) {
            char ch = truncated.charAt(i);

            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }

            if (ch == '{' || ch == '[') {
                depth++;
            } else if (ch == '}' || ch == ']') {
                depth--;
                if (depth == 1) {
                    lastCompleteEntry = i;
                }
            }
        }

        if (lastCompleteEntry > 0) {
            String partial = truncated.substring(0, lastCompleteEntry + 1);
            partial = partial.replaceAll(",\\s*$", "");
            partial = partial + closeChar;

            try {
                objectMapper.readTree(partial);
                log.error("[{}] Recovered truncated JSON: kept {} of {} chars",
                        getStepName(), partial.length(), truncated.length());
                return partial;
            } catch (Exception ignored) {
            }
        }

        return null;
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

    private boolean isSecurityDecisionTarget(Object targetTypeInfo) {
        return targetTypeInfo instanceof Class<?> targetClass
                && SecurityDecisionResponseLite.class.equals(targetClass);
    }

    private StructuredOutputPolicy resolveStructuredOutputPolicy(AIRequest<?> request, PipelineExecutionContext context) {
        Object configuredPolicy = null;
        if (request != null && request.getParameters().containsKey("structuredOutputPolicy")) {
            configuredPolicy = request.getParameters().get("structuredOutputPolicy");
        }
        if (configuredPolicy == null && context != null) {
            configuredPolicy = context.getMetadata("structuredOutputPolicy", Object.class);
        }
        return StructuredOutputPolicy.fromValue(configuredPolicy, StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
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
        if (!resolveStructuredOutputPolicy(request, context).allowsRawFallback()) {
            context.addMetadata("llmDecisionPresent", false);
            context.addMetadata("securityDecisionParsingFallbackApplied", false);
            context.addMetadata("syntheticSecurityDecisionApplied", false);
            throw new StructuredOutputExecutionException(
                    StructuredOutputFailureCategory.EMPTY_RESPONSE,
                    "Structured output fallback synthesis is forbidden");
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

