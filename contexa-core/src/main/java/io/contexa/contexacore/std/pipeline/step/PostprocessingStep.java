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


@Slf4j
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
            
            
            Class<?> targetResponseType = context.getMetadata("targetResponseType", Class.class);
            if (targetResponseType != null) {
                log.debug("[{}] 타겟 응답 타입: {}", getStepName(), targetResponseType.getSimpleName());
            }
            
            
            Object parsedResponse = context.getStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, Object.class);
            
            
            if (parsedResponse == null || 
                (parsedResponse instanceof String && ((String)parsedResponse).trim().isEmpty())) {
                log.warn("[{}] 응답이 비어있음, 향상된 기본 응답 생성", getStepName());
                return createEnhancedFallbackResponse(request, context);
            }
            
            
            if (parsedResponse != null) {
                
                Object wrappedResponse = parsedResponse;
                
                
                if (targetResponseType != null && targetResponseType.isInstance(parsedResponse)) {
                    log.debug("[{}] 파싱된 응답이 타겟 타입과 일치: {}", 
                        getStepName(), targetResponseType.getSimpleName());
                    
                    wrappedResponse = parsedResponse;
                } else {
                    
                    wrappedResponse = tryWrapWithDomainProcessor(parsedResponse, request, context);
                }
                
                
                enrichWithMetadata(wrappedResponse, request, context);
                context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, wrappedResponse);
                return wrappedResponse;
            }
            
            
            log.warn("[{}] 응답이 없음, 기본 응답 생성", getStepName());
            return createMinimalFallbackResponse(request, context);
        });
    }
    
    
    private <T extends DomainContext> Object tryWrapWithDomainProcessor(
            Object parsedResponse, AIRequest<T> request, PipelineExecutionContext context) {
        
        
        String templateKey = PromptGenerator.determineTemplateKey(request);

        if (templateKey == null) {
            log.debug("템플릿 키가 없어 도메인 프로세서를 사용하지 않음");
            return parsedResponse;
        }
        
        
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
    
    
    
    private void enrichWithMetadata(Object response, AIRequest<?> request, PipelineExecutionContext context) {
        
        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("executionTimeMs", executionTime);
            log.debug("[{}] 실행 시간: {}ms", getStepName(), executionTime);
        }
        
        
        context.addMetadata("status", "SUCCESS");
        context.addMetadata("completedAt", System.currentTimeMillis());
    }
    
    
    private Object createMinimalFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        DefaultAIResponse fallback = new DefaultAIResponse(
            request.getRequestId() != null ? request.getRequestId() : "unknown",
            "{\"status\":\"no_response\"}"
        );
        
        context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
        context.addMetadata("status", "FALLBACK");
        
        return fallback;
    }
    
    
    private Object createEnhancedFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        
        String error = context.getMetadata("error", String.class);
        String lastStage = context.getMetadata("lastCompletedStage", String.class);
        Long startTime = context.getMetadata("startTime", Long.class);
        
        
        String message = error != null ? error : "분석 결과를 생성할 수 없습니다";
        if (lastStage != null) {
            message += " (마지막 완료 단계: " + lastStage + ")";
        }
        
        
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
        return 6; 
    }
}