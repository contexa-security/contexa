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
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.ollama.api.ThinkOption;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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
            DecisionReplayCallResult callResult = executeRealDecisionCallWithQuickRetry(promptGenerationResult, round);
            rawResponseText = callResult.rawResponseText();

            pipelineContext.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, callResult.llmExecutionResult());
            pipelineContext.addMetadata("structuredOutputComplete", callResult.structuredOutputComplete());
            pipelineContext.addMetadata("sandboxDecisionBoundaryMode", "REAL_LLM_PROMPT_REPLAY");
            pipelineContext.addMetadata("sandboxPinnedModelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
            pipelineContext.addMetadata("sandboxLlmRetryCount", callResult.retryCount());
            pipelineContext.addMetadata("sandboxLlmFallbackApplied", callResult.fallbackApplied());
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
                pipelineContext.getMetadata("structuredOutputComplete", Boolean.class),
                buildRawRequest(round, promptSnapshot),
                rawResponseText,
                pipelineContext.getStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, Object.class),
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
                    .chatOptions(buildBenchmarkChatOptions(SandboxDecisionBenchmarkSettings.maxOutputTokens()))
                    .streamingMode(false)
                    .toolExecutionEnabled(false)
                    .advisorEnabled(false)
                    .build();
            executionContext.addMetadata("disableRetries", true);
            executionContext.addMetadata("disableOllamaThinking", true);
            return orchestrator.execute(executionContext);
        }
        return llmClient.call(promptGenerationResult.getPrompt());
    }

    private reactor.core.publisher.Mono<SecurityDecisionResponseLite> executeStructuredDecisionCall(
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
                    .chatOptions(buildBenchmarkChatOptions(SandboxDecisionBenchmarkSettings.maxOutputTokens()))
                    .streamingMode(false)
                    .toolExecutionEnabled(false)
                    .advisorEnabled(false)
                    .build();
            executionContext.addMetadata("disableRetries", true);
            executionContext.addMetadata("disableOllamaThinking", true);
            return orchestrator.executeEntity(executionContext, SecurityDecisionResponseLite.class);
        }
        return llmClient.entity(promptGenerationResult.getPrompt(), SecurityDecisionResponseLite.class);
    }

    private Mono<String> executeRepairDecisionCall(
            SandboxPromptReplayRound round,
            String previousResponse) {
        Prompt repairPrompt = new Prompt(List.of(
                SystemMessage.builder()
                        .text("""
                                You are a strict JSON normalizer for security decisions.
                                Rewrite the supplied content into exactly one JSON object.
                                Required keys: action, reasoning, riskScore, confidence, mitre.
                                action must be one of ALLOW, CHALLENGE, BLOCK, ESCALATE.
                                reasoning must be exactly one short sentence and no more than 24 words.
                                riskScore and confidence must be numeric values between 0.0 and 1.0.
                                mitre must be a string value or UNKNOWN.
                                Output JSON only.
                                """)
                        .build(),
                UserMessage.builder()
                        .text(buildRepairSuffix(previousResponse))
                        .build()));

        if (llmClient instanceof UnifiedLLMOrchestrator orchestrator) {
            ExecutionContext executionContext = ExecutionContext.builder()
                    .prompt(repairPrompt)
                    .requestId(round.requestId() + "-repair")
                    .userId(round.snapshot() != null && round.snapshot().event() != null
                            ? round.snapshot().event().getUserId()
                            : null)
                    .sessionId(round.snapshot() != null && round.snapshot().event() != null
                            ? round.snapshot().event().getSessionId()
                            : null)
                    .preferredModel(SandboxDecisionBenchmarkSettings.pinnedModelId())
                    .temperature(SandboxDecisionBenchmarkSettings.temperature())
                    .maxTokens(Math.max(128, SandboxDecisionBenchmarkSettings.maxOutputTokens()))
                    .chatOptions(buildBenchmarkChatOptions(Math.max(128, SandboxDecisionBenchmarkSettings.maxOutputTokens())))
                    .streamingMode(false)
                    .toolExecutionEnabled(false)
                    .advisorEnabled(false)
                    .build();
            executionContext.addMetadata("disableRetries", true);
            executionContext.addMetadata("sandboxDecisionRepairAttempt", true);
            executionContext.addMetadata("disableOllamaThinking", true);
            return orchestrator.execute(executionContext);
        }
        return llmClient.call(repairPrompt);
    }

    private DecisionReplayCallResult executeRealDecisionCallWithQuickRetry(
            PromptGenerationResult promptGenerationResult,
            SandboxPromptReplayRound round) {
        int attempts = 0;
        Exception lastFailure = null;
        while (attempts < 3) {
            attempts++;
            try {
                try {
                    SecurityDecisionResponseLite structuredResponse = executeStructuredDecisionCall(promptGenerationResult, round)
                            .timeout(Duration.ofSeconds(SandboxDecisionBenchmarkSettings.llmTimeoutSeconds()))
                            .block();
                     if (structuredResponse != null && hasStructuredDecisionFields(structuredResponse)) {
                         return new DecisionReplayCallResult(
                                 objectToJson(structuredResponse),
                                 structuredResponse,
                                true,
                                Math.max(0, attempts - 1),
                                false);
                    }
                } catch (Exception structuredFailure) {
                    lastFailure = structuredFailure;
                    if (isRetryableBusyFailure(structuredFailure)) {
                        if (attempts >= 3) {
                            break;
                        }
                        sleepQuietly(attempts == 1 ? 1500L : 3000L);
                        continue;
                    }
                }

                String rawResponse = executeRealDecisionCall(promptGenerationResult, round)
                        .timeout(Duration.ofSeconds(SandboxDecisionBenchmarkSettings.llmTimeoutSeconds()))
                        .block();
                if (!hasCanonicalDecisionPayload(rawResponse)) {
                    String repairedRawResponse = executeRepairDecisionCall(round, rawResponse)
                            .timeout(Duration.ofSeconds(SandboxDecisionBenchmarkSettings.llmTimeoutSeconds()))
                            .block();
                    if (hasCanonicalDecisionPayload(repairedRawResponse)) {
                        return new DecisionReplayCallResult(
                                repairedRawResponse,
                                repairedRawResponse,
                                false,
                                Math.max(0, attempts - 1),
                                true);
                    }
                    lastFailure = new IllegalStateException("LLM returned a non-canonical decision payload: " + rawResponse);
                    if (attempts >= 3) {
                        break;
                    }
                    sleepQuietly(attempts == 1 ? 1500L : 3000L);
                    continue;
                }
                return new DecisionReplayCallResult(
                        rawResponse,
                        rawResponse,
                        false,
                        Math.max(0, attempts - 1),
                        true);
            } catch (Exception exception) {
                lastFailure = exception;
                if (!isRetryableBusyFailure(exception) || attempts >= 3) {
                    break;
                }
                sleepQuietly(attempts == 1 ? 1500L : 3000L);
            }
        }
        if (lastFailure instanceof RuntimeException runtimeException) {
            throw runtimeException;
        }
        throw new IllegalStateException("Real LLM decision replay failed", lastFailure);
    }

    private boolean hasStructuredDecisionFields(SecurityDecisionResponseLite response) {
        if (response == null) {
            return false;
        }
        return isAllowedAction(response.getAction())
                && isCanonicalScore(response.getConfidence())
                && response.getReasoning() != null
                && !response.getReasoning().isBlank()
                && isCanonicalScore(response.getRiskScore())
                && response.getMitre() != null
                && !response.getMitre().isBlank();
    }

    private boolean hasCanonicalDecisionPayload(String rawResponse) {
        if (rawResponse == null || rawResponse.isBlank()) {
            return false;
        }
        try {
            Map<?, ?> payload = objectMapper.readValue(rawResponse, Map.class);
            return isCanonicalDecisionMap(payload);
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isIncompleteDecisionPayload(String rawResponse) {
        return !hasCanonicalDecisionPayload(rawResponse);
    }

    private boolean isMissingDecisionFields(Map<?, ?> payload) {
        return !isCanonicalDecisionMap(payload);
    }

    private boolean isMissingField(Object value) {
        if (value == null) {
            return true;
        }
        if (value instanceof String text) {
            return text.isBlank();
        }
        return false;
    }

    private boolean isCanonicalDecisionMap(Map<?, ?> payload) {
        if (payload == null || payload.isEmpty()) {
            return false;
        }
        return isAllowedAction(extractStringValue(payload.get("action")))
                && isCanonicalScore(payload.get("confidence"))
                && isCanonicalScore(payload.get("riskScore"))
                && hasNonBlankText(payload.get("reasoning"))
                && hasNonBlankText(payload.get("mitre"));
    }

    private boolean hasNonBlankText(Object value) {
        return value instanceof String text && !text.isBlank();
    }

    private String extractStringValue(Object value) {
        if (value instanceof String text) {
            return text.trim();
        }
        return null;
    }

    private boolean isAllowedAction(String action) {
        if (action == null || action.isBlank()) {
            return false;
        }
        return Arrays.asList("ALLOW", "CHALLENGE", "BLOCK", "ESCALATE").contains(action.trim().toUpperCase(Locale.ROOT));
    }

    private boolean isCanonicalScore(Object value) {
        if (value == null) {
            return false;
        }
        Double numericValue = null;
        if (value instanceof Number number) {
            numericValue = number.doubleValue();
        } else if (value instanceof String text && !text.isBlank()) {
            try {
                numericValue = Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return false;
            }
        }
        return numericValue != null && numericValue >= 0.0d && numericValue <= 1.0d;
    }

    private String buildRepairSuffix(String previousResponse) {
        String previous = previousResponse == null ? "null" : previousResponse.trim();
        if (previous.length() > 1200) {
            previous = previous.substring(0, 1200);
        }
        return """
                Normalize the following invalid security decision into the required schema.
                If the content signals missing baseline, ambiguity, or lack of trusted scope evidence for sensitive access, prefer CHALLENGE or ESCALATE over ALLOW.
                Invalid response:
                %s
                """.formatted(previous);
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
                    .chatOptions(buildBenchmarkChatOptions(24))
                    .streamingMode(false)
                    .toolExecutionEnabled(false)
                    .advisorEnabled(false)
                    .build();
            executionContext.addMetadata("disableRetries", true);
            executionContext.addMetadata("disableOllamaThinking", true);
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

    private boolean isRetryableBusyFailure(Throwable throwable) {
        if (throwable == null) {
            return false;
        }
        String message = throwable.getMessage();
        if (message != null) {
            String normalized = message.toLowerCase(Locale.ROOT);
            if (normalized.contains("maximum pending requests exceeded")
                    || normalized.contains("server busy, please try again")
                    || normalized.contains("transientaiexception")) {
                return true;
            }
        }
        return isRetryableBusyFailure(throwable.getCause());
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    private String objectToJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ignored) {
            return String.valueOf(value);
        }
    }

    private OllamaChatOptions buildBenchmarkChatOptions(int maxTokens) {
        OllamaChatOptions options = new OllamaChatOptions();
        options.setModel(SandboxDecisionBenchmarkSettings.pinnedModelId());
        options.setTemperature(SandboxDecisionBenchmarkSettings.temperature());
        options.setNumPredict(maxTokens);
        options.setFormat("json");
        options.setThinkOption(ThinkOption.ThinkBoolean.DISABLED);
        return options;
    }

    private record DecisionReplayCallResult(
            String rawResponseText,
            Object llmExecutionResult,
            boolean structuredOutputComplete,
            int retryCount,
            boolean fallbackApplied) {
    }
}
