package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Aspect
public class SandboxRealLlmExecutionAspect {

    @Around("execution(* io.contexa.contexacore.std.pipeline.step.LLMExecutionStep.execute(..)) && args(request, context)")
    public Object captureRealLlmTelemetry(
            ProceedingJoinPoint proceedingJoinPoint,
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context) throws Throwable {

        if (!SandboxDecisionBenchmarkSettings.useRealLlm()
                || SandboxDecisionBenchmarkExecutionMode.isPromptHarvest()) {
            return proceedingJoinPoint.proceed();
        }

        PromptGenerationResult promptGenerationResult = context.getStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                PromptGenerationResult.class);
        Map<String, Object> rawRequest = buildRawRequest(request, promptGenerationResult, context);
        long startedAt = System.currentTimeMillis();

        context.addMetadata("sandboxDecisionBoundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
        context.addMetadata("sandboxPinnedModelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        context.addMetadata("sandboxLlmRawRequest", rawRequest);

        Object proceeded = proceedingJoinPoint.proceed();
        if (!(proceeded instanceof Mono<?> mono)) {
            return proceeded;
        }

        return mono
                .doOnSuccess(response -> {
                    context.addMetadata("sandboxLlmRawResponse", response);
                    context.addMetadata("sandboxLlmRetryCount", 0);
                    context.addMetadata("sandboxLlmFallbackApplied", false);
                    context.addMetadata("sandboxLlmLatencyMs", System.currentTimeMillis() - startedAt);
                })
                .doOnError(error -> {
                    Map<String, Object> rawError = new LinkedHashMap<>();
                    rawError.put("errorType", error.getClass().getName());
                    rawError.put("message", error.getMessage());
                    context.addMetadata("sandboxLlmRawResponse", rawError);
                    context.addMetadata("sandboxLlmRetryCount", 0);
                    context.addMetadata("sandboxLlmFallbackApplied", false);
                    context.addMetadata("sandboxLlmLatencyMs", System.currentTimeMillis() - startedAt);
                });
    }

    private Map<String, Object> buildRawRequest(
            AIRequest<? extends DomainContext> request,
            PromptGenerationResult promptGenerationResult,
            PipelineExecutionContext context) {
        Map<String, Object> rawRequest = new LinkedHashMap<>();
        rawRequest.put("requestId", SandboxDecisionRequestIdResolver.resolve(request, context, promptGenerationResult));
        rawRequest.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        rawRequest.put("temperature", SandboxDecisionBenchmarkSettings.temperature());
        rawRequest.put("promptHash", context.getMetadata("promptHash", Object.class));
        rawRequest.put("systemPromptHash", context.getMetadata("systemPromptHash", Object.class));
        rawRequest.put("userPromptHash", context.getMetadata("userPromptHash", Object.class));
        rawRequest.put("rawPromptHash", context.getMetadata("rawPromptHash", Object.class));
        rawRequest.put("promptTransformationMode", context.getMetadata("promptTransformationMode", Object.class));
        rawRequest.put("budgetProfile", context.getMetadata("budgetProfile", Object.class));
        rawRequest.put("budgetViewProfile", context.getMetadata("budgetViewProfile", Object.class));
        rawRequest.put("estimatedTotalTokens", context.getMetadata("estimatedTotalTokens", Object.class));
        rawRequest.put("promptSectionSet", context.getMetadata("promptSectionSet", Object.class));
        rawRequest.put("omittedSections", context.getMetadata("omittedSections", Object.class));
        rawRequest.put("messages", serializeMessages(promptGenerationResult));
        return rawRequest;
    }

    private List<Map<String, Object>> serializeMessages(PromptGenerationResult promptGenerationResult) {
        if (promptGenerationResult == null || promptGenerationResult.getPrompt() == null) {
            return List.of();
        }
        return promptGenerationResult.getPrompt().getInstructions().stream()
                .map(message -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("messageType", message.getMessageType().name());
                    item.put("text", message.getText());
                    item.put("metadata", message.getMetadata());
                    return item;
                })
                .toList();
    }
}
