package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Test-only aspect that captures decision-layer outputs after PostprocessingStep succeeds.
 *
 * This gives CDC/ERA/SUHR a stable requestId anchor for:
 * - LLM step result
 * - parsed response
 * - final wrapped response
 * - prompt metadata used to reach that response
 */
@Aspect
public class SandboxDecisionPostprocessingAspect {

    private final SandboxDecisionTraceStore sandboxDecisionTraceStore;

    public SandboxDecisionPostprocessingAspect(SandboxDecisionTraceStore sandboxDecisionTraceStore) {
        this.sandboxDecisionTraceStore = sandboxDecisionTraceStore;
    }

    @Around("execution(* io.contexa.contexacore.std.pipeline.step.PostprocessingStep.execute(..)) && args(request, context)")
    public Object captureDecisionAfterPostprocessing(
            ProceedingJoinPoint proceedingJoinPoint,
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context) throws Throwable {

        Object proceeded = proceedingJoinPoint.proceed();
        if (!(proceeded instanceof Mono<?> mono)) {
            return proceeded;
        }

        return mono.doOnSuccess(response -> sandboxDecisionTraceStore.capture(buildSnapshot(request, context, response)));
    }

    private SandboxDecisionTraceSnapshot buildSnapshot(
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context,
            Object response) {

        PromptGenerationResult promptGenerationResult = context.getStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                PromptGenerationResult.class);

        Object llmExecutionResult = context.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, Object.class);
        Object parsedResponse = context.getStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, Object.class);

        Class<?> aiGenerationType = context.getMetadata("aiGenerationType", Class.class);
        Class<?> targetResponseType = context.getMetadata("targetResponseType", Class.class);
        Boolean structuredOutputComplete = context.getMetadata("structuredOutputComplete", Boolean.class);
        String boundaryMode = context.getMetadata("sandboxDecisionBoundaryMode", String.class);
        String modelId = context.getMetadata("sandboxPinnedModelId", String.class);
        Object llmRawRequest = context.getMetadata("sandboxLlmRawRequest", Object.class);
        Object llmRawResponse = context.getMetadata("sandboxLlmRawResponse", Object.class);
        String effectiveRequestId = SandboxDecisionRequestIdResolver.resolve(request, context, promptGenerationResult);

        return new SandboxDecisionTraceSnapshot(
                effectiveRequestId,
                Instant.now(),
                boundaryMode,
                modelId,
                aiGenerationType != null ? aiGenerationType.getName() : null,
                targetResponseType != null ? targetResponseType.getName() : null,
                structuredOutputComplete,
                llmRawRequest,
                llmRawResponse,
                llmExecutionResult,
                parsedResponse,
                response,
                promptGenerationResult != null ? promptGenerationResult.getRawSystemPrompt() : null,
                promptGenerationResult != null ? promptGenerationResult.getRawUserPrompt() : null,
                promptGenerationResult != null ? promptGenerationResult.getSystemPrompt() : null,
                promptGenerationResult != null ? promptGenerationResult.getUserPrompt() : null,
                promptGenerationResult != null ? promptGenerationResult.getMetadata() : Map.of(),
                promptGenerationResult != null ? promptGenerationResult.getPromptExecutionMetadata() : null,
                extractPipelineMetadata(context, response, llmExecutionResult, parsedResponse));
    }

    private Map<String, Object> extractPipelineMetadata(
            PipelineExecutionContext context,
            Object response,
            Object llmExecutionResult,
            Object parsedResponse) {
        Map<String, Object> pipelineMetadata = new LinkedHashMap<>();
        putIfPresent(pipelineMetadata, "executionId", context.getExecutionId());
        putIfPresent(pipelineMetadata, "structuredOutputComplete",
                context.getMetadata("structuredOutputComplete", Boolean.class));
        putIfPresent(pipelineMetadata, "parsingComplete",
                context.getMetadata("parsingComplete", Boolean.class));
        putIfPresent(pipelineMetadata, "executionTimeMs",
                context.getMetadata("executionTimeMs", Object.class));
        putIfPresent(pipelineMetadata, "status",
                context.getMetadata("status", String.class));
        putIfPresent(pipelineMetadata, "responseType",
                context.getMetadata("responseType", String.class));
        putIfPresent(pipelineMetadata, "responseClass",
                context.getMetadata("responseClass", String.class));
        putIfPresent(pipelineMetadata, "completedAt",
                context.getMetadata("completedAt", Object.class));
        putIfPresent(pipelineMetadata, "boundaryMode",
                context.getMetadata("sandboxDecisionBoundaryMode", String.class));
        putIfPresent(pipelineMetadata, "modelId",
                context.getMetadata("sandboxPinnedModelId", String.class));
        putIfPresent(pipelineMetadata, "llmRetryCount",
                context.getMetadata("sandboxLlmRetryCount", Object.class));
        putIfPresent(pipelineMetadata, "llmFallbackApplied",
                context.getMetadata("sandboxLlmFallbackApplied", Object.class));
        putIfPresent(pipelineMetadata, "llmLatencyMs",
                context.getMetadata("sandboxLlmLatencyMs", Object.class));
        putIfPresent(pipelineMetadata, "llmExecutionResultClass",
                llmExecutionResult != null ? llmExecutionResult.getClass().getName() : null);
        putIfPresent(pipelineMetadata, "parsedResponseClass",
                parsedResponse != null ? parsedResponse.getClass().getName() : null);
        putIfPresent(pipelineMetadata, "finalResponseClass",
                response != null ? response.getClass().getName() : null);
        return pipelineMetadata;
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }
}
