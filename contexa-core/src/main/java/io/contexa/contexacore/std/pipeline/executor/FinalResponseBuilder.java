package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Modifier;

@Slf4j
class FinalResponseBuilder {
    public <T extends DomainContext, R extends AIResponse> R build(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<R> responseType) {

        long responseStart = System.currentTimeMillis();
        log.info("[PIPELINE] 최종 응답 생성 시작: {}", request.getRequestId());

        // PostprocessingStep에서 처리된 결과를 타입 안전하게 가져오기
        R typedResult = context.getStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, responseType);
        
        if (typedResult != null) {
            log.info("[{}] POSTPROCESSING 결과 타입 안전 반환: {}",
                    "UNIVERSAL", responseType.getSimpleName());
            
            long responseTime = System.currentTimeMillis() - responseStart;
            log.info("[PIPELINE] 최종 응답 생성 완료: {}ms", responseTime);
            return typedResult;
        }
        
        // 타입 안전 변환이 실패한 경우, Object로 다시 시도
        Object postprocessingResult = context.getStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, Object.class);
        
        if (postprocessingResult != null) {
            log.warn("[{}] 타입 안전 변환 실패, 강제 캐스팅 시도: {} -> {}",
                    "UNIVERSAL", 
                    postprocessingResult.getClass().getSimpleName(), 
                    responseType.getSimpleName());
            
            if (responseType.isInstance(postprocessingResult)) {
                return responseType.cast(postprocessingResult);
            } else {
                log.error("[{}] 타입 불일치! 요청: {}, 실제: {}",
                        "UNIVERSAL", responseType.getSimpleName(), postprocessingResult.getClass().getSimpleName());
                // 최후의 수단: 강제 캐스팅 (ClassCastException 위험)
                try {
                    return responseType.cast(postprocessingResult);
                } catch (ClassCastException e) {
                    log.error("[{}] 강제 캐스팅 실패: {}", "UNIVERSAL", e.getMessage());
                    // 폴백 처리로 진행
                }
            }
        }

        // 결과가 null인 경우의 비상 폴백(fallback) 로직
        log.error("[{}] POSTPROCESSING 결과가 null! 긴급 fallback 생성", "UNIVERSAL");
        try {
            if (!responseType.isInterface() && !Modifier.isAbstract(responseType.getModifiers())) {
                return responseType.getDeclaredConstructor().newInstance();
            } else {
                // 간단한 Fallback AIResponse 구현체 생성
                AIResponse fallback = new AIResponse("pipeline-fallback", AIResponse.ExecutionStatus.SUCCESS) {
                    @Override
                    public Object getData() {
                        return "{\"status\":\"FALLBACK\",\"data\":\"Pipeline fallback response\"}";
                    }
                    
                    @Override
                    public String getResponseType() {
                        return "PIPELINE_FALLBACK";
                    }
                };
                return (R) fallback;
            }
        } catch (Exception e) {
            log.error("[{}] Fallback 생성도 실패!", "UNIVERSAL", e);
            throw new RuntimeException("Complete pipeline failure - no response generated", e);
        } finally {
            long responseTime = System.currentTimeMillis() - responseStart;
            log.info("[PIPELINE] 최종 응답 생성 완료: {}ms", responseTime);
        }
    }
}
