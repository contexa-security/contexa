package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 6단계: 후처리 단계 (도메인별 응답 래핑 포함)
 * 
 * ResponseParsingStep에서 파싱된 핵심 데이터를
 * 도메인별 응답 객체로 래핑하고 메타데이터를 추가합니다.
 * 
 * 역할:
 * - 도메인별 응답 래핑 (DomainResponseProcessor 사용)
 * - 최종 응답 검증
 * - 실행 시간 및 성공 상태 추가
 * - 필요 시 추가 메타데이터 설정
 */
@Slf4j
@Component
public class PostprocessingStep implements PipelineStep {
    
    private final List<DomainResponseProcessor> domainProcessors;
    
    @Autowired
    public PostprocessingStep(Optional<List<DomainResponseProcessor>> processors) {
        this.domainProcessors = processors
            .orElse(List.of())
            .stream()
            .sorted(Comparator.comparingInt(DomainResponseProcessor::getOrder))
            .toList();
        
        log.info("PostprocessingStep 초기화: {}개의 도메인 프로세서 등록", 
                this.domainProcessors.size());
    }
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            log.debug("[{}] 후처리 단계 실행", getStepName());
            
            // 타겟 응답 타입 확인
            Class<?> targetResponseType = context.getMetadata("targetResponseType", Class.class);
            if (targetResponseType != null) {
                log.debug("[{}] 타겟 응답 타입: {}", getStepName(), targetResponseType.getSimpleName());
            }
            
            // ResponseParsingStep 에서 이미 처리된 결과 확인
            Object parsedResponse = context.getStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, Object.class);
            
            // 빈 응답 처리 강화 - null 또는 빈 문자열 체크
            if (parsedResponse == null || 
                (parsedResponse instanceof String && ((String)parsedResponse).trim().isEmpty())) {
                log.warn("[{}] 응답이 비어있음, 향상된 기본 응답 생성", getStepName());
                return createEnhancedFallbackResponse(request, context);
            }
            
            // 도메인별 응답 래핑 처리
            if (parsedResponse != null) {
                // 타입 정보를 유지하면서 처리
                Object wrappedResponse = parsedResponse;
                
                // 타겟 타입과 일치하는지 확인
                if (targetResponseType != null && targetResponseType.isInstance(parsedResponse)) {
                    log.debug("[{}] 파싱된 응답이 타겟 타입과 일치: {}", 
                        getStepName(), targetResponseType.getSimpleName());
                    // 이미 올바른 타입이므로 도메인 프로세서를 건너뛸 수 있음
                    wrappedResponse = parsedResponse;
                } else {
                    // 도메인 프로세서로 래핑 시도
                    wrappedResponse = tryWrapWithDomainProcessor(parsedResponse, request, context);
                }
                
                // 메타데이터 추가
                enrichWithMetadata(wrappedResponse, request, context);
                context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, wrappedResponse);
                return wrappedResponse;
            }
            
            // 응답이 전혀 없는 경우
            log.warn("[{}] 응답이 없음, 기본 응답 생성", getStepName());
            return createMinimalFallbackResponse(request, context);
        });
    }
    
    /**
     * 도메인별 프로세서로 응답 래핑 시도
     */
    private <T extends DomainContext> Object tryWrapWithDomainProcessor(
            Object parsedResponse, AIRequest<T> request, PipelineExecutionContext context) {
        
        // 템플릿 키 확인
        String templateKey = PromptGenerator.determineTemplateKey(request);

        if (templateKey == null) {
            log.debug("템플릿 키가 없어 도메인 프로세서를 사용하지 않음");
            return parsedResponse;
        }
        
        // 적절한 도메인 프로세서 찾기
        for (DomainResponseProcessor processor : domainProcessors) {
            if (processor.supports(templateKey) || 
                processor.supportsType(parsedResponse.getClass())) {
                
                try {
                    Object wrappedResponse = processor.wrapResponse(
                        parsedResponse, 
                        context
                    );
                    
                    log.debug("도메인 프로세서 {}로 응답 래핑 완료", 
                             processor.getClass().getSimpleName());
                    return wrappedResponse;
                    
                } catch (Exception e) {
                    log.error("도메인 프로세서 실행 실패: {}", e.getMessage(), e);
                }
            }
        }
        
        log.debug("적합한 도메인 프로세서가 없어 원본 응답 반환");
        return parsedResponse;
    }
    
    
    /**
     * 메타데이터 추가 (최소화)
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
        context.addMetadata("status", "SUCCESS");
        context.addMetadata("completedAt", System.currentTimeMillis());
    }
    
    /**
     * 최소한의 Fallback 응답 생성
     */
    private Object createMinimalFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        DefaultAIResponse fallback = new DefaultAIResponse(
            request.getRequestId() != null ? request.getRequestId() : "unknown",
            "{\"status\":\"no_response\"}"
        );
        
        context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
        context.addMetadata("status", "FALLBACK");
        
        return fallback;
    }
    
    /**
     * 향상된 Fallback 응답 생성 - 더 자세한 오류 정보 포함
     */
    private Object createEnhancedFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        // 컨텍스트에서 오류 정보 추출
        String error = context.getMetadata("error", String.class);
        String lastStage = context.getMetadata("lastCompletedStage", String.class);
        Long startTime = context.getMetadata("startTime", Long.class);
        
        // 상세한 fallback 메시지 생성
        String message = error != null ? error : "분석 결과를 생성할 수 없습니다";
        if (lastStage != null) {
            message += " (마지막 완료 단계: " + lastStage + ")";
        }
        
        // SoarResponse 타입으로 생성 (클라이언트 호환성)
        Map<String, Object> fallbackData = new HashMap<>();
        fallbackData.put("status", "FALLBACK");
        fallbackData.put("message", message);
        fallbackData.put("timestamp", System.currentTimeMillis());
        fallbackData.put("requestId", request.getRequestId());
        if (lastStage != null) {
            fallbackData.put("lastCompletedStage", lastStage);
        }
        if (startTime != null) {
            fallbackData.put("processingTimeMs", System.currentTimeMillis() - startTime);
        }
        
        try {
            // JSON 문자열로 변환
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String jsonResponse = mapper.writeValueAsString(fallbackData);
            
            DefaultAIResponse fallback = new DefaultAIResponse(
                request.getRequestId() != null ? request.getRequestId() : "unknown",
                jsonResponse
            );
            
            context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
            context.addMetadata("status", "FALLBACK");
            
            return fallback;
        } catch (Exception e) {
            log.error("Fallback 응답 생성 실패", e);
            // 최소 fallback으로 폴백
            return createMinimalFallbackResponse(request, context);
        }
    }
    
    @Override
    public String getStepName() {
        return "POSTPROCESSING";
    }
    
    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null;
    }
    
    @Override
    public int getOrder() {
        return 6; // 여섯 번째 단계 (경량화)
    }
}