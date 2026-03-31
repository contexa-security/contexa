package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.PostprocessingStep;
import io.contexa.contexacore.std.pipeline.step.ResponseParsingStep;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class SandboxPromptTruthRealLlmDecisionReplayExecutor {

    private static final AtomicBoolean REAL_LLM_WARMED_UP = new AtomicBoolean(false);

    private final LLMClient llmClient;
    private final ObjectMapper objectMapper;
    private final ResponseParsingStep responseParsingStep;
    private final PostprocessingStep postprocessingStep;

    public SandboxPromptTruthRealLlmDecisionReplayExecutor(
            LLMClient llmClient,
            ObjectMapper objectMapper) {
        this.llmClient = llmClient;
        this.objectMapper = objectMapper;
        this.responseParsingStep = new ResponseParsingStep();
        this.postprocessingStep = new PostprocessingStep(java.util.Optional.of(List.of(new SecurityDecisionResponseProcessor())));
    }

    public SandboxPromptReplayRun replayDecisions(SandboxPromptReplayRun promptReplayRun) {
        List<SandboxPromptReplayRound> decisionRounds = new ArrayList<>(promptReplayRun.rounds().size());
        SandboxDecisionBenchmarkExecutionMode.set(SandboxDecisionBenchmarkExecutionMode.Mode.REAL_DECISION_REPLAY);
        try {
            warmUpRealLlmOnce();
            for (SandboxPromptReplayRound round : promptReplayRun.rounds()) {
                SandboxDecisionTraceSnapshot decisionSnapshot = executeDecision(round);
                decisionRounds.add(new SandboxPromptReplayRound(
                        round.phase(),
                        round.roundNumber(),
                        round.roundPlan(),
                        round.requestId(),
                        round.requestPath(),
                        round.clientIp(),
                        round.userAgentLabel(),
                        round.deviceId(),
                        round.responseBody(),
                        round.snapshot(),
                        decisionSnapshot));
            }
        } finally {
            SandboxDecisionBenchmarkExecutionMode.clear();
        }

        return new SandboxPromptReplayRun(
                promptReplayRun.benchmarkRunId(),
                promptReplayRun.username(),
                promptReplayRun.scenarioKey(),
                promptReplayRun.experimentGroup(),
                promptReplayRun.scenario(),
                decisionRounds);
    }

    private SandboxDecisionTraceSnapshot executeDecision(SandboxPromptReplayRound round) {
        SandboxPromptTraceSnapshot promptSnapshot = round.snapshot();
        if (promptSnapshot == null) {
            throw new IllegalStateException("Prompt snapshot is required for official decision replay. requestId=" + round.requestId());
        }

        SecurityDecisionRequest request = new SecurityDecisionRequest(new SecurityDecisionContext(
                promptSnapshot.event(),
                promptSnapshot.sessionContext(),
                promptSnapshot.behaviorAnalysis(),
                promptSnapshot.relatedDocuments()));
        PipelineExecutionContext pipelineContext = new PipelineExecutionContext("decision-replay-" + round.requestId());
        pipelineContext.addMetadata("startTime", System.currentTimeMillis());
        pipelineContext.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        pipelineContext.addMetadata("targetResponseType", SecurityDecisionResponseLite.class);
        copyPromptMetadata(promptSnapshot, pipelineContext);

        PromptGenerationResult promptGenerationResult = reconstructPromptGenerationResult(promptSnapshot);
        pipelineContext.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, promptGenerationResult);

        String rawResponseText = null;
        Object parsedResponse = null;
        Object finalResponse = null;
        Map<String, Object> pipelineMetadata = new LinkedHashMap<>();
        long startedAt = System.currentTimeMillis();

        try {
            rawResponseText = executeRealDecisionCall(promptGenerationResult, round)
                    .timeout(Duration.ofSeconds(SandboxDecisionBenchmarkSettings.llmTimeoutSeconds()))
                    .block();

            pipelineContext.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, rawResponseText);
            pipelineContext.addMetadata("structuredOutputComplete", false);
            pipelineContext.addMetadata("sandboxDecisionBoundaryMode", "REAL_LLM_PROMPT_REPLAY");
            pipelineContext.addMetadata("sandboxPinnedModelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
            pipelineContext.addMetadata("sandboxLlmRetryCount", 0);
            pipelineContext.addMetadata("sandboxLlmFallbackApplied", false);
            pipelineContext.addMetadata("sandboxLlmLatencyMs", System.currentTimeMillis() - startedAt);

            parsedResponse = responseParsingStep.execute(request, pipelineContext).block();
            finalResponse = postprocessingStep.execute(request, pipelineContext).block();
            pipelineMetadata.put("status", "SUCCESS");
        } catch (Exception exception) {
            Map<String, Object> errorPayload = new LinkedHashMap<>();
            errorPayload.put("errorType", exception.getClass().getName());
            errorPayload.put("message", safeErrorMessage(exception));
            rawResponseText = rawResponseText != null ? rawResponseText : objectToJson(errorPayload);
            pipelineContext.addMetadata("sandboxDecisionBoundaryMode", "REAL_LLM_PROMPT_REPLAY");
            pipelineContext.addMetadata("sandboxPinnedModelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
            pipelineContext.addMetadata("sandboxLlmRetryCount", 0);
            pipelineContext.addMetadata("sandboxLlmFallbackApplied", true);
            pipelineContext.addMetadata("sandboxLlmLatencyMs", System.currentTimeMillis() - startedAt);
            pipelineContext.addMetadata("status", "FAILED");
            pipelineMetadata.put("status", "FAILED");
            pipelineMetadata.put("errorType", exception.getClass().getName());
            pipelineMetadata.put("errorMessage", safeErrorMessage(exception));
        }

        pipelineMetadata.put("boundaryMode", "REAL_LLM_PROMPT_REPLAY");
        pipelineMetadata.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        putIfPresent(pipelineMetadata, "llmLatencyMs", pipelineContext.getMetadata("sandboxLlmLatencyMs", Object.class));
        putIfPresent(pipelineMetadata, "structuredOutputComplete", pipelineContext.getMetadata("structuredOutputComplete", Object.class));
        putIfPresent(pipelineMetadata, "parsedResponseClass", parsedResponse != null ? parsedResponse.getClass().getName() : null);
        putIfPresent(pipelineMetadata, "finalResponseClass", finalResponse != null ? finalResponse.getClass().getName() : null);
        putIfPresent(pipelineMetadata, "executionId", pipelineContext.getExecutionId());

        return new SandboxDecisionTraceSnapshot(
                round.requestId(),
                Instant.now(),
                "REAL_LLM_PROMPT_REPLAY",
                SandboxDecisionBenchmarkSettings.pinnedModelId(),
                SecurityDecisionResponseLite.class.getName(),
                SecurityDecisionResponseLite.class.getName(),
                false,
                buildRawRequest(round, promptSnapshot),
                rawResponseText,
                rawResponseText,
                parsedResponse,
                finalResponse,
                promptSnapshot.rawSystemPrompt(),
                promptSnapshot.rawUserPrompt(),
                promptSnapshot.systemPrompt(),
                promptSnapshot.userPrompt(),
                immutableWithoutNulls(promptSnapshot.metadata()),
                promptSnapshot.promptExecutionMetadata(),
                immutableWithoutNulls(pipelineMetadata));
    }

    private PromptGenerationResult reconstructPromptGenerationResult(SandboxPromptTraceSnapshot promptSnapshot) {
        Map<String, Object> metadata = new LinkedHashMap<>(promptSnapshot.metadata());
        Prompt prompt = new Prompt(List.of(
                SystemMessage.builder().text(promptSnapshot.systemPrompt()).metadata(metadata).build(),
                UserMessage.builder().text(promptSnapshot.userPrompt()).metadata(metadata).build()));
        return new PromptGenerationResult(
                prompt,
                promptSnapshot.systemPrompt(),
                promptSnapshot.userPrompt(),
                promptSnapshot.rawSystemPrompt(),
                promptSnapshot.rawUserPrompt(),
                metadata,
                promptSnapshot.promptExecutionMetadata());
    }

    private void copyPromptMetadata(SandboxPromptTraceSnapshot promptSnapshot, PipelineExecutionContext pipelineContext) {
        if (promptSnapshot.metadata() != null) {
            promptSnapshot.metadata().forEach(pipelineContext::addMetadata);
        }
        if (promptSnapshot.promptExecutionMetadata() != null) {
            promptSnapshot.promptExecutionMetadata().toMetadataMap().forEach(pipelineContext::addMetadata);
        }
    }

    private Map<String, Object> buildRawRequest(SandboxPromptReplayRound round, SandboxPromptTraceSnapshot promptSnapshot) {
        Map<String, Object> rawRequest = new LinkedHashMap<>();
        rawRequest.put("requestId", round.requestId());
        rawRequest.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        rawRequest.put("temperature", SandboxDecisionBenchmarkSettings.temperature());
        rawRequest.put("promptHash", promptSnapshot.metadata().get("promptHash"));
        rawRequest.put("systemPromptHash", promptSnapshot.metadata().get("systemPromptHash"));
        rawRequest.put("userPromptHash", promptSnapshot.metadata().get("userPromptHash"));
        rawRequest.put("rawPromptHash", promptSnapshot.metadata().get("rawPromptHash"));
        rawRequest.put("promptTransformationMode", promptSnapshot.metadata().get("promptTransformationMode"));
        rawRequest.put("budgetProfile", promptSnapshot.metadata().get("budgetProfile"));
        rawRequest.put("budgetViewProfile", promptSnapshot.metadata().get("budgetViewProfile"));
        rawRequest.put("estimatedTotalTokens", promptSnapshot.metadata().get("estimatedTotalTokens"));
        rawRequest.put("maxOutputTokens", SandboxDecisionBenchmarkSettings.maxOutputTokens());
        rawRequest.put("llmTimeoutSeconds", SandboxDecisionBenchmarkSettings.llmTimeoutSeconds());
        rawRequest.put("promptSectionSet", promptSnapshot.metadata().get("promptSectionSet"));
        rawRequest.put("omittedSections", promptSnapshot.metadata().get("omittedSections"));
        rawRequest.put("messages", List.of(
                Map.of("messageType", "SYSTEM", "text", promptSnapshot.systemPrompt()),
                Map.of("messageType", "USER", "text", promptSnapshot.userPrompt())));
        rawRequest.put("rawMessages", List.of(
                Map.of("messageType", "SYSTEM", "text", promptSnapshot.rawSystemPrompt()),
                Map.of("messageType", "USER", "text", promptSnapshot.rawUserPrompt())));
        return rawRequest;
    }

    private reactor.core.publisher.Mono<String> executeRealDecisionCall(
            PromptGenerationResult promptGenerationResult,
            SandboxPromptReplayRound round) {
        if (llmClient instanceof UnifiedLLMOrchestrator orchestrator) {
            ExecutionContext executionContext = ExecutionContext.builder()
                    .prompt(promptGenerationResult.getPrompt())
                    .requestId(round.requestId())
                    .userId(round.snapshot() != null && round.snapshot().event() != null
                            ? round.snapshot().event().getUserId()
                            : null)
                    .sessionId(round.snapshot() != null && round.snapshot().event() != null
                            ? round.snapshot().event().getSessionId()
                            : null)
                    .preferredModel(SandboxDecisionBenchmarkSettings.pinnedModelId())
                    .temperature(SandboxDecisionBenchmarkSettings.temperature())
                    .maxTokens(SandboxDecisionBenchmarkSettings.maxOutputTokens())
                    .streamingMode(false)
                    .toolExecutionEnabled(false)
                    .advisorEnabled(false)
                    .build();
            executionContext.addMetadata("disableRetries", true);
            return orchestrator.execute(executionContext);
        }
        return llmClient.call(promptGenerationResult.getPrompt());
    }

    private void warmUpRealLlmOnce() {
        if (!REAL_LLM_WARMED_UP.compareAndSet(false, true)) {
            return;
        }
        try {
            executeWarmupCall()
                    .timeout(Duration.ofSeconds(Math.max(60, SandboxDecisionBenchmarkSettings.llmTimeoutSeconds())))
                    .block();
        } catch (Exception ignored) {
            REAL_LLM_WARMED_UP.set(false);
        }
    }

    private reactor.core.publisher.Mono<String> executeWarmupCall() {
        Prompt warmupPrompt = new Prompt(List.of(
                SystemMessage.builder().text("Return JSON only. {\"action\":\"ALLOW\",\"reasoning\":\"warmup\",\"riskScore\":0.1,\"confidence\":0.1,\"mitre\":\"UNKNOWN\"}").build(),
                UserMessage.builder().text("Respond with a minimal valid JSON object for warmup.").build()));
        if (llmClient instanceof UnifiedLLMOrchestrator orchestrator) {
            ExecutionContext executionContext = ExecutionContext.builder()
                    .prompt(warmupPrompt)
                    .requestId("sandbox-real-llm-warmup")
                    .preferredModel(SandboxDecisionBenchmarkSettings.pinnedModelId())
                    .temperature(0.0d)
                    .maxTokens(24)
                    .streamingMode(false)
                    .toolExecutionEnabled(false)
                    .advisorEnabled(false)
                    .build();
            executionContext.addMetadata("disableRetries", true);
            return orchestrator.execute(executionContext);
        }
        return llmClient.call(warmupPrompt);
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (key == null || value == null) {
            return;
        }
        target.put(key, value);
    }

    private Map<String, Object> immutableWithoutNulls(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        LinkedHashMap<String, Object> sanitized = new LinkedHashMap<>();
        source.forEach((key, value) -> {
            if (key != null && value != null) {
                sanitized.put(key, value);
            }
        });
        return sanitized.isEmpty() ? Map.of() : Map.copyOf(sanitized);
    }

    private String safeErrorMessage(Exception exception) {
        if (exception == null) {
            return "Unknown replay failure";
        }
        if (exception.getMessage() != null && !exception.getMessage().isBlank()) {
            return exception.getMessage();
        }
        return exception.getClass().getSimpleName();
    }

    private String objectToJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ignored) {
            return String.valueOf(value);
        }
    }
}
