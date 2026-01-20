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
            log.debug("[{}] Spring AI StructuredOutputConverter를 사용한 응답 파싱 및 후처리 시작", getStepName());
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
                log.info("[{}] 이미 구조화된 출력 완료, 건너뜀. 타입: {}", 
                    getStepName(), structuredResponse != null ? structuredResponse.getClass().getSimpleName() : "null");
                context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, structuredResponse);
                context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, structuredResponse);
                context.addMetadata("parsingComplete", true);
                context.addMetadata("responseType", structuredResponse != null ? structuredResponse.getClass().getSimpleName() : "unknown");
                
                return structuredResponse;
            }
            
            String llmResponse = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, String.class);
            
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                log.warn("[{}] LLM 응답이 비어있음", getStepName());
                return createFallbackResponse(request, context);
            }
            
            Object targetTypeInfo = determineTargetType(request, context);
            Object result = convertWithSpringAI(llmResponse, targetTypeInfo, context);
            
            context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, result);
            context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, result);
            
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
            log.debug("[{}] 변환 시작 - targetTypeInfo 타입: {}",
                getStepName(), 
                targetTypeInfo != null ? targetTypeInfo.getClass().getName() : "null");
            
            log.debug("[{}] 추출된 JSON (첫 500자): {}", 
                getStepName(), 
                cleanJson.length() > 500 ? cleanJson.substring(0, 500) + "..." : cleanJson);

            switch (targetTypeInfo) {
                case Class<?> targetClass -> {
                    log.debug("[{}] targetClass: {}", getStepName(), targetClass.getName());

                    if (Map.class.isAssignableFrom(targetClass)) {
                        log.debug("[{}] Map 타입으로 변환 시도", getStepName());
                        MapOutputConverter converter = new MapOutputConverter();
                        Map<String, Object> result = converter.convert(cleanJson);
                        log.info("[{}] MapOutputConverter 변환 성공", getStepName());
                        return result;
                    } else if (List.class.isAssignableFrom(targetClass)) {
                        log.debug("[{}] List 타입으로 변환 시도", getStepName());
                        ListOutputConverter converter = new ListOutputConverter(conversionService);
                        List<String> result = converter.convert(cleanJson);
                        log.info("[{}] ListOutputConverter 변환 성공", getStepName());
                        return result;
                    } else {
                        log.debug("[{}] Bean 타입으로 변환 시도: {}", getStepName(), targetClass.getSimpleName());
                        try {
                            BeanOutputConverter<?> converter = new BeanOutputConverter<>(targetClass);
                            Object result = converter.convert(cleanJson);
                            log.info("[{}] BeanOutputConverter 변환 성공: {}", getStepName(), targetClass.getSimpleName());
                            return result;
                        } catch (Exception beanEx) {
                            log.error("[{}] BeanOutputConverter 실패 ({}): {}",
                                    getStepName(), targetClass.getSimpleName(), beanEx.getMessage());

                            log.debug("[{}] 폴백: Map으로 변환 시도", getStepName());
                            MapOutputConverter mapConverter = new MapOutputConverter();
                            Map<String, Object> mapResult = mapConverter.convert(cleanJson);
                            log.warn("[{}] Map으로 변환 성공 (Bean 변환 실패)", getStepName());
                            return mapResult;
                        }
                    }
                }
                case ParameterizedTypeReference<?> typeRef -> {
                    BeanOutputConverter<?> converter = new BeanOutputConverter<>(typeRef);
                    Object result = converter.convert(cleanJson);
                    log.info("[{}] BeanOutputConverter(제네릭) 변환 성공", getStepName());
                    return result;
                }
                case StructuredOutputConverter<?> converter -> {
                    Object result = converter.convert(cleanJson);
                    log.info("[{}] 커스텀 StructuredOutputConverter 변환 성공", getStepName());
                    return result;
                }
                case null, default -> {
                    log.debug("[{}] 타입 정보 없음, Map 으로 기본 변환 시도", getStepName());
                    MapOutputConverter converter = new MapOutputConverter();
                    return converter.convert(cleanJson);
                }
            }
            
        } catch (Exception e) {
            log.error("[{}] Spring AI 변환 실패: {}", getStepName(), e.getMessage());
            log.error("[{}] 상세 오류 정보: ", getStepName(), e);

            try {
                String fallbackJson = extractJson(response);
                log.warn("[{}] 폴백: JSON 문자열 그대로 반환 (변환 실패)", getStepName());
                return fallbackJson;
            } catch (Exception fallbackError) {
                log.error("[{}] 최종 폴백 실패: {}", getStepName(), fallbackError.getMessage());
                return response;
            }
        }
    }
    
    
    private String extractJson(String response) {
        if (response == null || response.trim().isEmpty()) {
            return "{}";
        }
        
        String cleaned = response.trim();
        
        
        if (cleaned.toLowerCase().contains("this is a json") || 
            cleaned.toLowerCase().contains("json (javascript object notation)") ||
            cleaned.toLowerCase().contains("here is the json") ||
            cleaned.toLowerCase().contains("json structure") ||
            cleaned.toLowerCase().contains("json format")) {
            
            log.warn("[{}] AI가 JSON을 설명하는 텍스트를 반환함. JSON 추출 시도...", getStepName());
            
            
            int jsonStart = -1;
            int jsonEnd = -1;
            
            
            for (int i = 0; i < cleaned.length(); i++) {
                if (cleaned.charAt(i) == '{' || cleaned.charAt(i) == '[') {
                    jsonStart = i;
                    break;
                }
            }

            
            if (jsonStart >= 0) {
                char startChar = cleaned.charAt(jsonStart);
                char endChar = (startChar == '{') ? '}' : ']';
                int braceCount = 0;
                
                for (int i = jsonStart; i < cleaned.length(); i++) {
                    if (cleaned.charAt(i) == startChar) {
                        braceCount++;
                    } else if (cleaned.charAt(i) == endChar) {
                        braceCount--;
                        if (braceCount == 0) {
                            jsonEnd = i + 1;
                            break;
                        }
                    }
                }
                
                if (jsonEnd > jsonStart) {
                    cleaned = cleaned.substring(jsonStart, jsonEnd);
                    log.info("[{}] JSON 블록 추출 성공", getStepName());
                }
            }
        }
        
        
        if (cleaned.contains("```json")) {
            int start = cleaned.indexOf("```json") + 7;
            int end = cleaned.indexOf("```", start);
            if (end > start) {
                cleaned = cleaned.substring(start, end).trim();
            }
        }
        
        else if (cleaned.startsWith("```") && cleaned.endsWith("```")) {
            
            cleaned = cleaned.substring(3);
            
            if (cleaned.endsWith("```")) {
                cleaned = cleaned.substring(0, cleaned.length() - 3);
            }
            cleaned = cleaned.trim();
            
            
            int firstNewline = cleaned.indexOf('\n');
            if (firstNewline > 0 && firstNewline < 20) {
                String firstLine = cleaned.substring(0, firstNewline).trim();
                
                if (firstLine.matches("^[a-zA-Z]+$")) {
                    cleaned = cleaned.substring(firstNewline + 1).trim();
                }
            }
        }
        
        else if (cleaned.contains("```")) {
            
            int start = cleaned.indexOf("```");
            if (start >= 0) {
                
                String afterStart = cleaned.substring(start + 3);
                
                int end = afterStart.indexOf("```");
                if (end > 0) {
                    cleaned = afterStart.substring(0, end).trim();
                    
                    int firstNewline = cleaned.indexOf('\n');
                    if (firstNewline > 0 && firstNewline < 20) {
                        String firstLine = cleaned.substring(0, firstNewline).trim();
                        if (firstLine.matches("^[a-zA-Z]+$")) {
                            cleaned = cleaned.substring(firstNewline + 1).trim();
                        }
                    }
                }
            }
        }
        
        
        if (cleaned.isEmpty() || cleaned.equals("{}") || cleaned.equals("[]")) {
            return cleaned.isEmpty() ? "{}" : cleaned;
        }
        
        
        if (cleaned.startsWith("{") || cleaned.startsWith("[")) {
            try {
                objectMapper.readTree(cleaned);
                return cleaned;
            } catch (Exception e) {
                log.debug("JSON 파싱 실패: {}", e.getMessage());
                
                
                try {
                    
                    cleaned = cleaned.replaceAll(",\\s*([}\\]])", "$1");
                    
                    objectMapper.readTree(cleaned);
                    return cleaned;
                } catch (Exception retryError) {
                    log.debug("JSON 복구 실패: {}", retryError.getMessage());
                }
            }
        }
        
        
        log.debug("JSON 형식이 아님, 원본 반환");
        return response;
    }
    
    
    private Object determineTargetType(AIRequest<?> request, PipelineExecutionContext context) {
        log.debug("[{}] determineTargetType 시작", getStepName());
        
        
        Class<?> aiGenerationType = context.getMetadata("aiGenerationType", Class.class);
        if (aiGenerationType != null) {
            log.debug("[{}] aiGenerationType 사용: {}", getStepName(), aiGenerationType.getName());
            return aiGenerationType;
        }
        
        
        Object typeFromContext = context.getMetadata("targetResponseType", Object.class);
        if (typeFromContext != null) {
            log.debug("[{}] Context에서 targetResponseType 발견: {}", 
                getStepName(), 
                typeFromContext instanceof Class ? ((Class<?>)typeFromContext).getName() : typeFromContext.getClass().getName());
            return typeFromContext;
        }
        
        
        Object typeFromRequest = request.getParameter("responseType", Object.class);
        if (typeFromRequest != null) {
            log.debug("[{}] Request parameter에서 responseType 발견: {}", 
                getStepName(),
                typeFromRequest instanceof Class ? ((Class<?>)typeFromRequest).getName() : typeFromRequest.getClass().getName());
            return typeFromRequest;
        }
        
        
        Object converter = request.getParameter("outputConverter", Object.class);
        if (converter instanceof StructuredOutputConverter) {
            log.debug("[{}] StructuredOutputConverter 발견", getStepName());
            return converter;
        }
        
        
        log.debug("[{}] 타입 정보 없음 - 기본값 Map.class 사용", getStepName());
        return Map.class;
    }
    
    
    private void enrichWithMetadata(Object response, AIRequest<?> request, PipelineExecutionContext context) {
        
        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("executionTimeMs", executionTime);
            log.debug("[{}] 실행 시간: {}ms", getStepName(), executionTime);
        }
        
        
        context.addMetadata("status", response != null ? "SUCCESS" : "FAILURE");
        context.addMetadata("completedAt", System.currentTimeMillis());
        
        
        if (response != null) {
            context.addMetadata("responseClass", response.getClass().getName());
            context.addMetadata("responseSize", estimateResponseSize(response));
        }
    }
    
    
    private int estimateResponseSize(Object response) {
        if (response instanceof String) {
            return ((String) response).length();
        } else if (response instanceof Map) {
            return ((Map<?, ?>) response).size();
        } else if (response instanceof List) {
            return ((List<?>) response).size();
        }
        return 1; 
    }
    
    
    private Object createFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        log.warn("[{}] Fallback 응답 생성", getStepName());
        
        DefaultAIResponse fallback = new DefaultAIResponse(
            request.getRequestId() != null ? request.getRequestId() : "unknown",
            Map.of("error", "No response from LLM", "status", "fallback")
        );
        
        
        enrichWithMetadata(fallback, request, context);
        
        context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, fallback);
        context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
        
        return fallback;
    }
    
    @Override
    public String getStepName() {
        return "RESPONSE_PARSING";
    }

    @Override
    public int getOrder() {
        return 5; 
    }
}