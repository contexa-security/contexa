package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingPipelineContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingPipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * LLMExecutionStep을 확장한 스트리밍 지원 버전
 */
@Slf4j
@Component
@Qualifier("streamingLLMExecutionStep")
public class StreamingLLMExecutionStep extends LLMExecutionStep {

    public StreamingLLMExecutionStep(ToolCapableLLMClient llmClient) {
        super(llmClient);
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request,
            PipelineExecutionContext context) {

        if (context instanceof StreamingPipelineContext streamingContext) {
            if (streamingContext.isStreamingMode()) {
                return executeWithStreaming(request, streamingContext);
            }
        }

        return super.execute(request, context);
    }

    private <T extends DomainContext> Mono<Object> executeWithStreaming(
            AIRequest<T> request,
            StreamingPipelineContext context) {

        log.info("[STREAMING-LLM] 스트리밍 모드 LLM 실행 시작 - 스레드: {}",
                Thread.currentThread().getName());

        return Mono.fromCallable(() -> {
                    // 프롬프트 가져오기
                    StreamingPipelineExecutionContext executionContext = (StreamingPipelineExecutionContext) context;

                    PromptGenerator.PromptGenerationResult promptResult =
                            executionContext.getStepResult(
                                    PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                                    PromptGenerator.PromptGenerationResult.class
                            );

                    if (promptResult == null || promptResult.getPrompt() == null) {
                        throw new IllegalStateException("No prompt found in context");
                    }

                    return promptResult.getPrompt();
                })
                // 프롬프트 준비를 Virtual Thread 에서 실행
                .flatMap(prompt -> {
                    StringBuilder rawResponseCollector = new StringBuilder();

                    // LLM 스트림도 독립적인 스케줄러에서 실행
                    Flux<String> llmStream = getLlmClient().stream(prompt);

                    return llmStream
                            .doOnNext(chunk -> {
                                // 청크 처리 로직...
                                if (chunk.startsWith("###STREAMING###")) {
                                    String streamingText = chunk.substring(15);
                                    rawResponseCollector.append(streamingText);

                                    if (context.getStreamSink() != null && context.isStreamingMode()) {
                                        context.getStreamSink().tryEmitNext(streamingText);
                                    }
                                } else {
                                    rawResponseCollector.append(chunk);
                                    if (context.getStreamSink() != null && context.isStreamingMode()) {
                                        context.getStreamSink().tryEmitNext(chunk);
                                    }
                                }
                            })
                            .doOnComplete(() -> {
                                String fullRawResponse = rawResponseCollector.toString();
                                StreamingPipelineExecutionContext executionContext = (StreamingPipelineExecutionContext) context;
                                executionContext.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, fullRawResponse);

                                log.info("[STREAMING-LLM] LLM 실행 완료 - 스레드: {}",
                                        Thread.currentThread().getName());
                            })
                            .then(Mono.just(rawResponseCollector.toString()))
                            .cast(Object.class);
                });
    }
}