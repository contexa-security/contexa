package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * 2단계: 전처리 단계
 * 
 * SRP: 오직 시스템 메타데이터 구성만 담당
 * OCP: 확장 가능한 메타데이터 구성
 * 
 * 역할:
 * - 요청 정보를 바탕으로 시스템 메타데이터 구성
 * - 프롬프트 생성에 필요한 컨텍스트 정보 준비
 * - 로깅 및 디버깅 정보 수집
 */
@Slf4j
public class PreprocessingStep implements PipelineStep {
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            log.debug("[{}] 전처리 단계 실행", getStepName());
            
            // 시스템 메타데이터 구성
            String systemMetadata = buildSystemMetadata(request);
            
            // 결과를 context에 저장하여 다음 단계로 전달
            context.addStepResult(PipelineConfiguration.PipelineStep.PREPROCESSING, systemMetadata);
            
            log.debug("[{}] 시스템 메타데이터 생성 완료: {} characters", 
                     getStepName(), systemMetadata.length());
            
            return systemMetadata;
        });
    }
    
    /**
     * 시스템 메타데이터 구성 (확장 가능)
     */
    protected <T extends DomainContext> String buildSystemMetadata(AIRequest<T> request) {
        return String.format("""
            시스템 정보:
            - 요청 ID: %s
            - 요청 타입: %s
            - 컨텍스트 타입: %s
            - 처리 시간: %s
            """, 
            request.getRequestId(),
            request.getClass().getSimpleName(),
            request.getContext().getClass().getSimpleName(),
            java.time.LocalDateTime.now()
        );
    }
    
    @Override
    public String getStepName() {
        return "PREPROCESSING";
    }
    
    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && request.getRequestId() != null;
    }
    
    @Override
    public int getOrder() {
        return 2; // 두 번째 단계
    }
} 