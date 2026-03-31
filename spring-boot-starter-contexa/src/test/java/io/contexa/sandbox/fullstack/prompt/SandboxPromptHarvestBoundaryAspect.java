package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

@Aspect
public class SandboxPromptHarvestBoundaryAspect {

    private final ObjectMapper objectMapper;

    public SandboxPromptHarvestBoundaryAspect(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Around("execution(* io.contexa.contexacore.std.pipeline.step.LLMExecutionStep.execute(..)) && args(request, context)")
    public Object shortCircuitDuringPromptHarvest(
            ProceedingJoinPoint proceedingJoinPoint,
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context) throws Throwable {

        if (!SandboxDecisionBenchmarkSettings.useRealLlm()
                || !SandboxDecisionBenchmarkExecutionMode.isPromptHarvest()) {
            return proceedingJoinPoint.proceed();
        }

        PromptGenerationResult promptGenerationResult = context.getStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                PromptGenerationResult.class);
        Map<String, Object> stableResponse = SandboxStableDecisionSynthesizer.synthesize(request, context);
        Class<?> targetType = context.getMetadata("aiGenerationType", Class.class);
        if (targetType == null) {
            targetType = context.getMetadata("targetResponseType", Class.class);
        }

        Object responseBody = targetType != null
                ? objectMapper.convertValue(stableResponse, targetType)
                : objectMapper.writeValueAsString(stableResponse);

        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, responseBody);
        context.addMetadata("structuredOutputComplete", targetType != null);
        context.addMetadata("sandboxDecisionBoundaryMode", "PROMPT_HARVEST_STABLE");
        context.addMetadata("sandboxPinnedModelId", "PROMPT_HARVEST_STABLE");
        context.addMetadata("sandboxLlmRetryCount", 0);
        context.addMetadata("sandboxLlmFallbackApplied", false);
        context.addMetadata("sandboxLlmLatencyMs", 1L);
        context.addMetadata("sandboxLlmRawRequest", buildRawRequest(request, context, promptGenerationResult));
        context.addMetadata("sandboxLlmRawResponse", stableResponse);

        return Mono.just(responseBody);
    }

    private Map<String, Object> buildRawRequest(
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context,
            PromptGenerationResult promptGenerationResult) {
        Map<String, Object> rawRequest = new LinkedHashMap<>();
        rawRequest.put("requestId", SandboxDecisionRequestIdResolver.resolve(request, context, promptGenerationResult));
        rawRequest.put("boundaryMode", "PROMPT_HARVEST_STABLE");
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
        return rawRequest;
    }
}
