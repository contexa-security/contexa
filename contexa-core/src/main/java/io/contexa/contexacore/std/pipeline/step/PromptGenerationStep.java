package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacommon.mcp.tool.ToolResolver;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Mono;

@Slf4j
public class PromptGenerationStep implements PipelineStep {
    
    private final PromptGenerator promptGenerator;
    private final ToolResolver chainedToolResolver;

    public PromptGenerationStep(
            PromptGenerator promptGenerator,
            @Autowired(required = false) ToolResolver chainedToolResolver) {
        this.promptGenerator = promptGenerator;
        this.chainedToolResolver = chainedToolResolver;
    }
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request, 
            PipelineExecutionContext context) {
        
        return Mono.fromCallable(() -> {
                        
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
                            }

            context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, promptResult);

            ToolCallback[] availableTools = chainedToolResolver != null
                ? chainedToolResolver.getAllToolCallbacks()
                : new ToolCallback[0];
            logPromptGenerationDetails(promptResult, availableTools);

            return promptResult;
        });
    }

    private void logPromptGenerationDetails(
            PromptGenerator.PromptGenerationResult promptResult,
            ToolCallback[] availableTools) {

        if (log.isDebugEnabled()) {
                        for (ToolCallback tool : availableTools) {
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
        return 3; 
    }
    
}