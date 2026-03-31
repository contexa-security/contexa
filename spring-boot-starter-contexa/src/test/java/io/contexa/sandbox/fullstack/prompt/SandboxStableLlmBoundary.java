package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.mockito.Mockito;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * sandbox replay에서 최종 LLM 경계만 안정화한다.
 *
 * 컨텍스트와 프롬프트가 지금의 핵심 검증 대상이므로,
 * 마지막 LLM 응답만 고정하고 그 이전 웹/MFA/컨텍스트/프롬프트 생성 흐름은 실제 런타임을 그대로 탄다.
 */
public final class SandboxStableLlmBoundary {

    private SandboxStableLlmBoundary() {
    }

    public static void configure(ObjectMapper objectMapper, LLMExecutionStep llmExecutionStep) {
        SandboxStableDecisionCaptureStore.clearAll();

        Mockito.reset(llmExecutionStep);
        Mockito.when(llmExecutionStep.getConfigStep()).thenReturn(PipelineConfiguration.PipelineStep.LLM_EXECUTION);
        Mockito.when(llmExecutionStep.getOrder()).thenReturn(4);
        Mockito.when(llmExecutionStep.canExecute(Mockito.any())).thenReturn(true);
        Mockito.doAnswer(invocation -> {
            AIRequest<?> request = invocation.getArgument(0);
            PipelineExecutionContext context = invocation.getArgument(1);
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
            context.addMetadata("sandboxDecisionBoundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
            context.addMetadata("sandboxPinnedModelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
            context.addMetadata("sandboxLlmRetryCount", 0);
            context.addMetadata("sandboxLlmFallbackApplied", false);
            context.addMetadata("sandboxLlmLatencyMs", 1L);
            Object rawRequest = buildRawRequest(context, targetType);
            context.addMetadata("sandboxLlmRawRequest", rawRequest);
            context.addMetadata("sandboxLlmRawResponse", stableResponse);
            String effectiveRequestId = SandboxDecisionRequestIdResolver.resolve(request, context, promptGenerationResult);
            SandboxStableDecisionCaptureStore.capture(new SandboxStableDecisionCaptureStore.StableDecisionCapture(
                    effectiveRequestId,
                    SandboxDecisionBenchmarkSettings.boundaryMode(),
                    SandboxDecisionBenchmarkSettings.pinnedModelId(),
                    targetType != null ? targetType.getName() : null,
                    targetType != null ? targetType.getName() : null,
                    targetType != null,
                    rawRequest,
                    stableResponse,
                    responseBody,
                    buildPipelineMetadata(context, responseBody)));
            return reactor.core.publisher.Mono.just(responseBody);
        }).when(llmExecutionStep).execute(Mockito.any(), Mockito.any());
    }

    private static Map<String, Object> buildRawRequest(PipelineExecutionContext context, Class<?> targetType) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("targetType", targetType != null ? targetType.getName() : null);
        request.put("promptHash", context.getMetadata("promptHash", Object.class));
        request.put("systemPromptHash", context.getMetadata("systemPromptHash", Object.class));
        request.put("userPromptHash", context.getMetadata("userPromptHash", Object.class));
        request.put("promptTransformationMode", context.getMetadata("promptTransformationMode", Object.class));
        request.put("promptSectionSet", context.getMetadata("promptSectionSet", Object.class));
        request.put("omittedSections", context.getMetadata("omittedSections", Object.class));
        request.put("estimatedTotalTokens", context.getMetadata("estimatedTotalTokens", Object.class));
        request.put("llmTotalPromptLength", context.getMetadata("llmTotalPromptLength", Object.class));
        return request;
    }

    private static Map<String, Object> buildPipelineMetadata(PipelineExecutionContext context, Object responseBody) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("executionId", context.getExecutionId());
        metadata.put("structuredOutputComplete", context.getMetadata("structuredOutputComplete", Object.class));
        metadata.put("boundaryMode", context.getMetadata("sandboxDecisionBoundaryMode", Object.class));
        metadata.put("modelId", context.getMetadata("sandboxPinnedModelId", Object.class));
        metadata.put("llmRetryCount", context.getMetadata("sandboxLlmRetryCount", Object.class));
        metadata.put("llmFallbackApplied", context.getMetadata("sandboxLlmFallbackApplied", Object.class));
        metadata.put("llmLatencyMs", context.getMetadata("sandboxLlmLatencyMs", Object.class));
        metadata.put("llmExecutionResultClass", responseBody != null ? responseBody.getClass().getName() : null);
        metadata.put("parsedResponseClass", responseBody != null ? responseBody.getClass().getName() : null);
        metadata.put("finalResponseClass", responseBody != null ? responseBody.getClass().getName() : null);
        return metadata;
    }
}
