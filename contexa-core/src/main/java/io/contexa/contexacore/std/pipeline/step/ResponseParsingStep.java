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

/**
 * 5단계: 응답 파싱 및 후처리 통합 단계
 * Spring AI의 StructuredOutputConverter를 활용한 최적화된 구현:
 * - BeanOutputConverter: Java 클래스/레코드 변환
 * - MapOutputConverter: Map<String, Object> 변환
 * - ListOutputConverter: List<T> 변환
 * - PostprocessingStep의 기능을 통합하여 중복 제거
 * - getAIGenerationType()을 통한 타입 안전성 보장
 * Spring AI 공식 표준을 완벽하게 준수하는 구현
 */
@Slf4j
@Component
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
    
    /**
     * Spring AI StructuredOutputConverter를 사용한 통합 변환
     * 타입에 따라 적절한 컨버터 선택 (BeanOutputConverter, MapOutputConverter, ListOutputConverter)
     */
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
    
    /**
     * 개선된 JSON 추출 - 다양한 형식 지원
     * - ```json ... ``` 블록
     * - ``` ... ``` 일반 코드 블록  
     * - 빈 JSON 객체/배열 처리
     * - 여러 줄에 걸친 JSON 지원
     * - JSON 설명 텍스트 감지 및 처리
     */
    private String extractJson(String response) {
        if (response == null || response.trim().isEmpty()) {
            return "{}";
        }
        
        String cleaned = response.trim();
        
        // JSON 설명 텍스트 감지 (AI가 JSON을 설명하는 경우)
        if (cleaned.toLowerCase().contains("this is a json") || 
            cleaned.toLowerCase().contains("json (javascript object notation)") ||
            cleaned.toLowerCase().contains("here is the json") ||
            cleaned.toLowerCase().contains("json structure") ||
            cleaned.toLowerCase().contains("json format")) {
            
            log.warn("[{}] AI가 JSON을 설명하는 텍스트를 반환함. JSON 추출 시도...", getStepName());
            
            // JSON 블록을 찾아서 추출 시도
            int jsonStart = -1;
            int jsonEnd = -1;
            
            // { 로 시작하는 첫 번째 위치 찾기
            for (int i = 0; i < cleaned.length(); i++) {
                if (cleaned.charAt(i) == '{' || cleaned.charAt(i) == '[') {
                    jsonStart = i;
                    break;
                }
            }

            // } 또는 ]로 끝나는 마지막 위치 찾기
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
        
        // 1. JSON 코드 블록 처리 (```json ... ```)
        if (cleaned.contains("```json")) {
            int start = cleaned.indexOf("```json") + 7;
            int end = cleaned.indexOf("```", start);
            if (end > start) {
                cleaned = cleaned.substring(start, end).trim();
            }
        }
        // 2. 일반 코드 블록 처리 (``` ... ```)
        else if (cleaned.startsWith("```") && cleaned.endsWith("```")) {
            // 시작 ``` 제거
            cleaned = cleaned.substring(3);
            // 끝 ``` 제거
            if (cleaned.endsWith("```")) {
                cleaned = cleaned.substring(0, cleaned.length() - 3);
            }
            cleaned = cleaned.trim();
            
            // 첫 줄이 언어 지정자인 경우 제거 (예: ```javascript)
            int firstNewline = cleaned.indexOf('\n');
            if (firstNewline > 0 && firstNewline < 20) {
                String firstLine = cleaned.substring(0, firstNewline).trim();
                // 언어 지정자 패턴 확인 (알파벳으로만 구성되고 20자 미만)
                if (firstLine.matches("^[a-zA-Z]+$")) {
                    cleaned = cleaned.substring(firstNewline + 1).trim();
                }
            }
        }
        // 3. 다른 형식의 코드 블록 처리
        else if (cleaned.contains("```")) {
            // 첫 번째 ```를 찾음
            int start = cleaned.indexOf("```");
            if (start >= 0) {
                // ``` 이후부터 시작
                String afterStart = cleaned.substring(start + 3);
                // 다음 ```를 찾음
                int end = afterStart.indexOf("```");
                if (end > 0) {
                    cleaned = afterStart.substring(0, end).trim();
                    // 첫 줄이 언어 지정자인 경우 제거
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
        
        // 4. 빈 JSON 처리 (공백만 있는 경우도 포함)
        if (cleaned.isEmpty() || cleaned.equals("{}") || cleaned.equals("[]")) {
            return cleaned.isEmpty() ? "{}" : cleaned;
        }
        
        // 5. JSON 유효성 검증
        if (cleaned.startsWith("{") || cleaned.startsWith("[")) {
            try {
                objectMapper.readTree(cleaned);
                return cleaned;
            } catch (Exception e) {
                log.debug("JSON 파싱 실패: {}", e.getMessage());
                
                // 6. 복구 시도: 일반적인 JSON 오류 수정
                try {
                    // 후행 쉼표 제거
                    cleaned = cleaned.replaceAll(",\\s*([}\\]])", "$1");
                    // 재시도
                    objectMapper.readTree(cleaned);
                    return cleaned;
                } catch (Exception retryError) {
                    log.debug("JSON 복구 실패: {}", retryError.getMessage());
                }
            }
        }
        
        // 7. JSON이 아닌 경우 원본 반환
        log.debug("JSON 형식이 아님, 원본 반환");
        return response;
    }
    
    /**
     * 타겟 타입 결정 로직 (Spring AI 표준 준수)
     */
    private Object determineTargetType(AIRequest<?> request, PipelineExecutionContext context) {
        log.debug("[{}] determineTargetType 시작", getStepName());
        
        // 1. PromptGenerationStep 에서 설정한 AI 생성 타입 확인 (우선순위 가장 높음)
        Class<?> aiGenerationType = context.getMetadata("aiGenerationType", Class.class);
        if (aiGenerationType != null) {
            log.debug("[{}] aiGenerationType 사용: {}", getStepName(), aiGenerationType.getName());
            return aiGenerationType;
        }
        
        // 2. Context에서 타입 정보 확인 - UniversalPipelineExecutor에서 설정한 값
        Object typeFromContext = context.getMetadata("targetResponseType", Object.class);
        if (typeFromContext != null) {
            log.debug("[{}] Context에서 targetResponseType 발견: {}", 
                getStepName(), 
                typeFromContext instanceof Class ? ((Class<?>)typeFromContext).getName() : typeFromContext.getClass().getName());
            return typeFromContext;
        }
        
        // 3. Request parameter에서 확인
        Object typeFromRequest = request.getParameter("responseType", Object.class);
        if (typeFromRequest != null) {
            log.debug("[{}] Request parameter에서 responseType 발견: {}", 
                getStepName(),
                typeFromRequest instanceof Class ? ((Class<?>)typeFromRequest).getName() : typeFromRequest.getClass().getName());
            return typeFromRequest;
        }
        
        // 4. StructuredOutputConverter 확인
        Object converter = request.getParameter("outputConverter", Object.class);
        if (converter instanceof StructuredOutputConverter) {
            log.debug("[{}] StructuredOutputConverter 발견", getStepName());
            return converter;
        }
        
        // 5. 기본값: Map
        log.debug("[{}] 타입 정보 없음 - 기본값 Map.class 사용", getStepName());
        return Map.class;
    }
    
    /**
     * 메타데이터 풍부화 (PostprocessingStep 기능 통합)
     * 실행 시간, 성공 상태 등의 메타데이터를 추가합니다.
     */
    private void enrichWithMetadata(Object response, AIRequest<?> request, PipelineExecutionContext context) {
        // 실행 시간 계산
        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("executionTimeMs", executionTime);
            log.debug("[{}] 실행 시간: {}ms", getStepName(), executionTime);
        }
        
        // 성공 상태 설정
        context.addMetadata("status", response != null ? "SUCCESS" : "FAILURE");
        context.addMetadata("completedAt", System.currentTimeMillis());
        
        // 응답 타입 정보
        if (response != null) {
            context.addMetadata("responseClass", response.getClass().getName());
            context.addMetadata("responseSize", estimateResponseSize(response));
        }
    }
    
    /**
     * 응답 크기 추정
     */
    private int estimateResponseSize(Object response) {
        if (response instanceof String) {
            return ((String) response).length();
        } else if (response instanceof Map) {
            return ((Map<?, ?>) response).size();
        } else if (response instanceof List) {
            return ((List<?>) response).size();
        }
        return 1; // 기본값
    }
    
    /**
     * Fallback 응답 생성 (PostprocessingStep 기능 통합)
     */
    private Object createFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        log.warn("[{}] Fallback 응답 생성", getStepName());
        
        DefaultAIResponse fallback = new DefaultAIResponse(
            request.getRequestId() != null ? request.getRequestId() : "unknown",
            Map.of("error", "No response from LLM", "status", "fallback")
        );
        
        // 메타데이터 추가
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
        return 5; // 다섯 번째 단계 (PostprocessingStep 기능 통합)
    }
}