package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * 1단계: 컨텍스트 검색 단계
 *
 * SRP: 오직 컨텍스트 검색만 담당
 * OCP: Registry 패턴으로 새로운 Retriever 추가 가능
 *
 * 역할:
 * - Context 타입에 따라 적절한 ContextRetriever 선택
 * - RAG 검색 또는 데이터베이스 조회 수행
 * - 검색 결과를 다음 단계로 전달
 */
@Slf4j
public class ContextRetrievalStep implements PipelineStep {

    private final ContextRetrieverRegistry contextRetrieverRegistry;

    public ContextRetrievalStep(ContextRetrieverRegistry contextRetrieverRegistry) {
        this.contextRetrieverRegistry = contextRetrieverRegistry;
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            log.debug("[{}] 컨텍스트 검색 단계 실행", getStepName());

            ContextRetriever contextRetriever = contextRetrieverRegistry.getRetriever(request.getContext());
            ContextRetriever.ContextRetrievalResult contextResult = contextRetriever.retrieveContext(request);

            // 결과를 context에 저장하여 다음 단계로 전달
            context.addStepResult(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL, contextResult);

            // 디버깅용 contextInfo 로그
            String debugContextInfo = contextResult != null ? contextResult.getContextInfo() : "null";
            log.debug("[{}] contextInfo 생성됨 ({}): {}",
                    getStepName(),
                    contextRetriever.getClass().getSimpleName(),
                    debugContextInfo.substring(0, Math.min(100, debugContextInfo.length())));

            return contextResult;
        });
    }

    @Override
    public String getStepName() {
        return "CONTEXT_RETRIEVAL";
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && request.getContext() != null;
    }

    @Override
    public int getOrder() {
        return 1; // 첫 번째 단계
    }
}