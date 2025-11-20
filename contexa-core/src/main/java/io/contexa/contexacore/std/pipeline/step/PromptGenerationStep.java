package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacommon.mcp.tool.ChainedToolResolver;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * 개선된 프롬프트 생성 단계 V2
 * 
 * Tool-Aware 프롬프트 생성을 지원하여 AI 모델이
 * 사용 가능한 도구를 정확히 인지할 수 있도록 합니다.
 * 
 * 이 컴포넌트는 기존 PromptGenerationStep을 대체하여
 * 도구 정보를 프롬프트에 통합합니다.
 */
@Slf4j
@Component
public class PromptGenerationStep implements PipelineStep {
    
    private final PromptGenerator promptGenerator;
    private final ChainedToolResolver chainedToolResolver;

    public PromptGenerationStep(
            PromptGenerator promptGenerator,
            @Autowired(required = false) ChainedToolResolver chainedToolResolver) {
        this.promptGenerator = promptGenerator;
        this.chainedToolResolver = chainedToolResolver;
    }
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request, 
            PipelineExecutionContext context) {
        
        return Mono.fromCallable(() -> {
            log.info("✏️ [{}] Tool-Aware 프롬프트 생성 단계 실행", getStepName());
            
            ContextRetriever.ContextRetrievalResult contextResult =
                context.getStepResult(
                    PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL, 
                    ContextRetriever.ContextRetrievalResult.class
                );
            
            String systemMetadata = context.getStepResult(
                PipelineConfiguration.PipelineStep.PREPROCESSING, 
                String.class
            );

                String contextInfo = contextResult != null ? contextResult.getContextInfo() : "";
                String metadata = systemMetadata != null ? systemMetadata : "";
                PromptGenerator.PromptGenerationResult promptResult = promptGenerator.generatePrompt(request, contextInfo, metadata);

            Class<?> aiGenerationType = promptGenerator.getAIGenerationType(request);
            if (aiGenerationType != null) {
                context.addMetadata("aiGenerationType", aiGenerationType);
                log.debug("AI 생성 타입 설정: {}", aiGenerationType.getSimpleName());
            }

            context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, promptResult);

            // ChainedToolResolver가 있으면 Tool 정보 로깅
            ToolCallback[] availableTools = chainedToolResolver != null
                ? chainedToolResolver.getAllToolCallbacks()
                : new ToolCallback[0];
            logPromptGenerationDetails(promptResult, availableTools);

            return promptResult;
        });
    }

    /**
     * 프롬프트 생성 상세 로깅
     */
    private void logPromptGenerationDetails(
            PromptGenerator.PromptGenerationResult promptResult,
            ToolCallback[] availableTools) {
        
        log.info("Tool-Aware 프롬프트 생성 완료:");
        log.info("  - 시스템 프롬프트 길이: {} 문자", 
            promptResult.getSystemPrompt() != null ? promptResult.getSystemPrompt().length() : 0);
        log.info("  - 사용자 프롬프트 길이: {} 문자", 
            promptResult.getUserPrompt() != null ? promptResult.getUserPrompt().length() : 0);
        log.info("  - 통합된 도구 수: {} 개", availableTools.length);
        
        if (log.isDebugEnabled()) {
            log.debug("도구 목록:");
            for (ToolCallback tool : availableTools) {
                log.debug("  - {}: {}", 
                    tool.getToolDefinition().name(),
                    tool.getToolDefinition().description());
            }
        }
    }
    
    @Override
    public String getStepName() {
        return "PROMPT_GENERATION";
    }
    
    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && promptGenerator != null;
    }
    
    @Override
    public int getOrder() {
        return 3; // 세 번째 단계 (기존과 동일)
    }
    
}