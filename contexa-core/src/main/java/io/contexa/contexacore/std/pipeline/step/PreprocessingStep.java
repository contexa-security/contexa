package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


@Slf4j
public class PreprocessingStep implements PipelineStep {
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            log.debug("[{}] 전처리 단계 실행", getStepName());
            
            
            String systemMetadata = buildSystemMetadata(request);
            
            
            context.addStepResult(PipelineConfiguration.PipelineStep.PREPROCESSING, systemMetadata);
            
            log.debug("[{}] 시스템 메타데이터 생성 완료: {} characters", 
                     getStepName(), systemMetadata.length());
            
            return systemMetadata;
        });
    }
    
    
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
        return 2; 
    }
} 