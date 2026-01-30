package io.contexa.contexacore.std.pipeline.step;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.ai.converter.ListOutputConverter;
import org.springframework.ai.converter.MapOutputConverter;
import org.springframework.ai.converter.StructuredOutputConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Slf4j
public class ResponseParsingStep implements PipelineStep {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DefaultConversionService conversionService = new DefaultConversionService();
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
                        String finalResponse = context.getStepResult(PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION, String.class);
            if(finalResponse != null){
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
            
            String llmResponse = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, String.class);
            
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                log.error("[{}] LLM response is empty", getStepName());
                return createFallbackResponse(request, context);
            }
            
            Object targetTypeInfo = determineTargetType(request, context);
            Object result = convertWithSpringAI(llmResponse, targetTypeInfo, context);
            
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
                        Map<String, Object> result = converter.convert(cleanJson);
                                                return result;
                    } else if (List.class.isAssignableFrom(targetClass)) {
                                                ListOutputConverter converter = new ListOutputConverter(conversionService);
                        List<String> result = converter.convert(cleanJson);
                                                return result;
                    } else {
                                                try {
                            BeanOutputConverter<?> converter = new BeanOutputConverter<>(targetClass);
                            Object result = converter.convert(cleanJson);
                                                        return result;
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
                    Object result = converter.convert(cleanJson);
                                        return result;
                }
                case StructuredOutputConverter<?> converter -> {
                    Object result = converter.convert(cleanJson);
                                        return result;
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

    private String extractJson(String response) {
        if (response == null || response.trim().isEmpty()) {
            return "{}";
        }

        String cleaned = response.trim();

        // Handle markdown code blocks with json language specifier
        if (cleaned.contains("```json")) {
            int start = cleaned.indexOf("```json") + 7;
            int end = cleaned.indexOf("```", start);
            if (end > start) {
                cleaned = cleaned.substring(start, end).trim();
            }
        }
        // Handle generic markdown code blocks
        else if (cleaned.contains("```")) {
            int start = cleaned.indexOf("```") + 3;
            int end = cleaned.indexOf("```", start);
            if (end > start) {
                String content = cleaned.substring(start, end).trim();
                // Skip language identifier if present on first line
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

        // Validate JSON structure
        if (cleaned.startsWith("{") || cleaned.startsWith("[")) {
            try {
                objectMapper.readTree(cleaned);
                return cleaned;
            } catch (Exception e) {
                // Try fixing trailing commas
                try {
                    String fixed = cleaned.replaceAll(",\\s*([}\\]])", "$1");
                    objectMapper.readTree(fixed);
                    return fixed;
                } catch (Exception retryError) {
                    log.error("[{}] Invalid JSON structure: {}", getStepName(), e.getMessage());
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

    private Object createFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        log.error("[{}] Creating fallback response", getStepName());
        
        DefaultAIResponse fallback = new DefaultAIResponse(
            request.getRequestId() != null ? request.getRequestId() : "unknown",
            Map.of("error", "No response from LLM", "status", "fallback")
        );

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