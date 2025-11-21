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

/**
 * 4단계: LLM 실행 단계 (최종 리팩토링 버전)
 *
 * 단일 책임 원칙 (SRP) 강화:
 * - 이 클래스는 파이프라인 단계를 '조율'하는 책임만 가집니다.
 * (프롬프트 준비 -> LLMClient 위임 -> 결과 저장)
 * - 실제 LLM 호출의 복잡성은 LLMClient에 의해 완전히 숨겨집니다.
 *
 * 테스트 용이성 향상:
 * - 테스트 시 Mock LLMClient를 주입하여 이 클래스의 로직만 독립적으로 테스트할 수 있습니다.
 */
@Slf4j
@RequiredArgsConstructor
public class LLMExecutionStep implements PipelineStep {

    private final LLMClient llmClient;

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        long stepStartTime = System.currentTimeMillis();
        log.info("[PIPELINE-STEP] ===== LLM 실행 단계 시작 ===== Request: {}", request.getRequestId());

        // AI 생성 타입 확인 (우선순위: aiGenerationType > targetResponseType > responseType)
        Class<?> targetType = context.getMetadata("aiGenerationType", Class.class);
        if (targetType == null) {
            targetType = context.getMetadata("targetResponseType", Class.class);
        }
        if (targetType == null) {
            targetType = request.getParameter("responseType", Class.class);
        }
        
        final Class<?> finalTargetType = targetType;
        
        // AI 생성 타입이 설정된 경우 로깅
        if (context.getMetadata("aiGenerationType", Class.class) != null) {
            log.debug("AI 생성 타입 사용: {}", finalTargetType.getSimpleName());
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
                        // 폴백: 일반 String 호출
                        return preparePrompt(context)
                                .flatMap(llmClient::call)
                                .doOnSuccess(response -> {
                                    context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                                    logResponseSuccess(request.getRequestId(), response, stepStartTime);
                                })
                                .cast(Object.class);
                    });
        }
        
        // 기존 String 기반 처리
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
                    return Mono.just(""); // 에러 발생 시 빈 문자열로 폴백
                });
    }

    public <T extends DomainContext> Flux<String> executeStreaming(AIRequest<T> request, PipelineExecutionContext context) {
        log.info("[PIPELINE-STEP] 스트리밍 LLM 실행 시작: {}", request.getRequestId());

        return preparePrompt(context)
                .flatMapMany(prompt -> {
                    log.info("[PIPELINE-STEP] 일반 스트리밍 LLM 실행: {}", request.getRequestId());
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
            log.info("[PIPELINE-STEP] 프롬프트 준비 완료 (System: {}자, User: {}자)",
                    promptResult.getSystemPrompt().length(), promptResult.getUserPrompt().length());
            return promptResult.getPrompt();
        }).onErrorResume(IllegalStateException.class, e -> {
            log.warn("[PIPELINE-STEP] {}", e.getMessage());
            return Mono.empty(); // 프롬프트가 없으면 빈 Mono를 반환하여 flatMap 체인을 중단
        });
    }

    private void logResponseSuccess(String requestId, String response, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.info("[PIPELINE-STEP] ===== LLM 실행 완료 ===== Request: {}, 총 시간: {}ms, 응답 길이: {}자",
                requestId, totalTime, response != null ? response.length() : 0);
    }
    
    private void logStructuredResponseSuccess(String requestId, Object response, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.info("[PIPELINE-STEP] ===== 구조화된 LLM 실행 완료 ===== Request: {}, 총 시간: {}ms, 응답 타입: {}",
                requestId, totalTime, response != null ? response.getClass().getSimpleName() : "null");
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