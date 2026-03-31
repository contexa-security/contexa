package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
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
        Map<String, Object> stableResponse = new LinkedHashMap<>();
        stableResponse.put("action", "ALLOW");
        stableResponse.put("reasoning",
                "Sandbox full-stack replay stabilizes only the final LLM boundary so context and prompt quality can be verified deterministically.");
        stableResponse.put("riskScore", 0.10d);
        stableResponse.put("confidence", 0.70d);
        stableResponse.put("mitre", "UNKNOWN");

        Mockito.reset(llmExecutionStep);
        Mockito.when(llmExecutionStep.getConfigStep()).thenReturn(PipelineConfiguration.PipelineStep.LLM_EXECUTION);
        Mockito.when(llmExecutionStep.getOrder()).thenReturn(4);
        Mockito.when(llmExecutionStep.canExecute(Mockito.any())).thenReturn(true);
        Mockito.doAnswer(invocation -> {
            PipelineExecutionContext context = invocation.getArgument(1);
            Class<?> targetType = context.getMetadata("aiGenerationType", Class.class);
            if (targetType == null) {
                targetType = context.getMetadata("targetResponseType", Class.class);
            }
            Object responseBody = targetType != null
                    ? objectMapper.convertValue(stableResponse, targetType)
                    : objectMapper.writeValueAsString(stableResponse);

            context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, responseBody);
            context.addMetadata("structuredOutputComplete", targetType != null);
            return reactor.core.publisher.Mono.just(responseBody);
        }).when(llmExecutionStep).execute(Mockito.any(), Mockito.any());
    }
}
