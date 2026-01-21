package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator.PromptGenerationResult;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Qualifier;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class LLMExecutionStep implements PipelineStep {

    private final LLMClient llmClient;

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        long stepStartTime = System.currentTimeMillis();

        Class<?> targetType = context.getMetadata("aiGenerationType", Class.class);
        if (targetType == null) {
            targetType = context.getMetadata("targetResponseType", Class.class);
        }
        if (targetType == null) {
            targetType = request.getParameter("responseType", Class.class);
        }
        
        final Class<?> finalTargetType = targetType;

        if (context.getMetadata("aiGenerationType", Class.class) != null) {
                    }
        
        if (finalTargetType != null) {
            return preparePrompt(context)
                    .flatMap(prompt -> llmClient.entity(prompt, finalTargetType))
                    .doOnSuccess(response -> {
                        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                        context.addMetadata("structuredOutputComplete", true);
                        logStructuredResponseSuccess(request.getRequestId(), response, stepStartTime);
                    })
                    .cast(Object.class)
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .onErrorResume(error -> {
                        log.warn("구조화된 출력 실행 오류. String 폴백 시도. Request: {}", request.getRequestId());
                        
                        return preparePrompt(context)
                                .flatMap(llmClient::call)
                                .doOnSuccess(response -> {
                                    context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                                    logResponseSuccess(request.getRequestId(), response, stepStartTime);
                                })
                                .cast(Object.class);
                    });
        }

        return preparePrompt(context)
                .flatMap(llmClient::call)
                .doOnSuccess(response -> {
                    context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                    logResponseSuccess(request.getRequestId(), response, stepStartTime);
                })
                .cast(Object.class)
                .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                .onErrorResume(error -> {
                    log.warn("LLM 실행 오류 발생. 빈 문자열로 폴백합니다. Request: {}", request.getRequestId());
                    return Mono.just(""); 
                });
    }

    public <T extends DomainContext> Flux<String> executeStreaming(AIRequest<T> request, PipelineExecutionContext context) {
        
        return preparePrompt(context)
                .flatMapMany(prompt -> {
                                        return llmClient.stream(prompt);
                })
                .doOnError(error -> log.error("[PIPELINE-STEP] 스트리밍 처리 실패: {}", request.getRequestId(), error));
    }

    private Mono<Prompt> preparePrompt(PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            PromptGenerationResult promptResult = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PROMPT_GENERATION, PromptGenerationResult.class);

            if (promptResult == null || promptResult.getPrompt() == null) {
                throw new IllegalStateException("Prompt not found in context. Skipping LLM execution.");
            }
                        return promptResult.getPrompt();
        }).onErrorResume(IllegalStateException.class, e -> {
            log.warn("[PIPELINE-STEP] {}", e.getMessage());
            return Mono.empty(); 
        });
    }

    private void logResponseSuccess(String requestId, String response, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
            }
    
    private void logStructuredResponseSuccess(String requestId, Object response, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
            }

    private void logError(String requestId, Throwable error, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.error("[PIPELINE-STEP] ===== LLM 실행 실패 ===== Request: {}, 총 시간: {}ms, 오류: {}",
                requestId, totalTime, error.getMessage());
    }

    @Override
    public String getStepName() { return "LLM_EXECUTION"; }

    public LLMClient getLlmClient() {
        return llmClient;
    }

    @Override
    public int getOrder() { return 4; }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return llmClient != null;
    }
}