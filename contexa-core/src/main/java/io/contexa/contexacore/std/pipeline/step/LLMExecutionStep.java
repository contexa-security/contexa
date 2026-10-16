/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.ObservedPromptTokenUsageRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapability;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.observation.SecurityDecisionObservationContextResolver;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector.Inspection;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.client.advisor.StructuredOutputValidationAdvisor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Locale;
import java.util.List;
import java.util.concurrent.TimeoutException;

@Slf4j
public class LLMExecutionStep implements PipelineStep {

    private static final String OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED";

    private final SecurityDecisionRawOutputContractInspector rawOutputContractInspector =
            new SecurityDecisionRawOutputContractInspector();

    private static final List<String> EXECUTION_METADATA_KEYS = List.of(
            "requestedModelId",
            "requestedModelSourceKey",
            "preferredModel",
            "selectedModelId",
            "selectedModelProvider",
            "runtimeModelId",
            "modelSelectionSource",
            "modelSelectionFallbackUsed",
            "modelSelectionFailure",
            "modelSelectionCandidates",
            "temperature",
            "topP",
            "seed",
            "maxTokens",
            "openAiReasoningEffort",
            "openAiVerbosity",
            "disableRetries",
            "disableOllamaThinking",
            "decisionBoundaryMode",
            "structuredOutputMode",
            "structuredOutputPolicy",
            "structuredOutputValidationMaxAttempts",
            "providerResponseId",
            "providerResponseModel",
            "actualPromptTokens",
            "actualCompletionTokens",
            "actualTotalTokens",
            "actualTokenUsageAvailable",
            "promptCacheHit",
            "cachedPromptTokens",
            ExecutionContext.DETERMINISM_NOT_APPLIED,
            ExecutionContext.PROVIDER_REASONING_EFFORT,
            "providerFinishReason",
            "promptCacheKeyApplied",
            ExecutionContext.OUTPUT_SCHEMA_APPLIED,
            "chatModelClass",
            "providerModelSelectionMs",
            "providerChatClientBuildMs",
            "providerPromptSpecPrepareMs",
            "providerThrottleEnabled",
            "providerThrottleSkippedReason",
            "providerThrottleWaitMs",
            "providerThrottleEstimatedTokens",
            "providerThrottleRequestsPerMinute",
            "providerThrottleTokensPerMinute",
            "providerThrottleMaxWaitMs",
            "providerRetryCount",
            "providerCallMs",
            "providerCallTimeoutMs",
            "providerCallExceededTimeout",
            "providerCallFailed",
            "providerCallFailureCategory",
            "providerCallFailureClass",
            "providerCallFailureMessage",
            "openAiCallMs",
            "providerResponseMetadataMs",
            "responseExtractMs"
    );

    private final LLMClient llmClient;
    private final StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry;

    public LLMExecutionStep(LLMClient llmClient) {
        this(llmClient, StructuredOutputCapabilityRegistry.defaultRegistry());
    }

    public LLMExecutionStep(LLMClient llmClient, StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        this.llmClient = llmClient;
        this.structuredOutputCapabilityRegistry = structuredOutputCapabilityRegistry != null
                ? structuredOutputCapabilityRegistry
                : StructuredOutputCapabilityRegistry.defaultRegistry();
    }

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
        final StructuredOutputCapability capability = resolveStructuredOutputCapability(request, context, finalTargetType);
        final StructuredOutputMode structuredOutputMode = resolveStructuredOutputMode(request, context, finalTargetType, capability);
        final StructuredOutputPolicy structuredOutputPolicy = resolveStructuredOutputPolicy(request, context, finalTargetType);
        context.addMetadata("structuredOutputProviderFamily", capability.providerFamily());
        context.addMetadata("structuredOutputNativeSupported", capability.nativeStructuredSupported());
        context.addMetadata("structuredOutputValidationAdvisorSupported", capability.validationAdvisorSupported());
        context.addMetadata("structuredOutputCapabilitySource", capability.resolutionSource());

        if (isSecurityDecisionTarget(finalTargetType)) {
            context.addMetadata("entityExecutionAttempted", false);
            context.addMetadata("entityExecutionSucceeded", false);
            context.addMetadata("rawExecutionAttempted", true);
            context.addMetadata("structuredOutputComplete", false);
            context.addMetadata("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED");
            context.addMetadata("structuredOutputPolicy", structuredOutputPolicy.name());
            context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
            return preparePrompt(context)
                    .flatMap(prompt -> executeSecurityDecisionRawGuarded(prompt, request, context)
                            .switchIfEmpty(Mono.error(new IllegalStateException("Security decision LLM raw execution returned empty Mono")))
                            .doOnSuccess(rawResponse -> {
                                context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, rawResponse);
                                context.addMetadata("rawExecutionSucceeded", true);
                                context.addMetadata("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED");
                                context.addMetadata("structuredOutputPolicy", structuredOutputPolicy.name());
                                context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
                            }))
                    .cast(Object.class)
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .doFinally(signalType -> {
                        long elapsedMs = System.currentTimeMillis() - stepStartTime;
                        context.addMetadata("llmExecutionLatencyMs", elapsedMs);
                        context.addMetadata("llmStepMs", elapsedMs);
                        log.info("[PIPELINE-STEP] LLM execution completed - Request: {}, Signal: {}, Duration: {}ms",
                                request.getRequestId(), signalType, elapsedMs);
                    })
                    .onErrorResume(error -> {
                        log.error("[PIPELINE-STEP] Security decision raw execution failed; fail-closed parsing will produce a challenge. Request: {}",
                                request.getRequestId(), error);
                        String failureCategory = rawExecutionFailureCategory(context, error);
                        context.addMetadata("rawExecutionSucceeded", false);
                        context.addMetadata("structuredOutputFailureCategory", failureCategory);
                        context.addMetadata("securityDecisionParseFailureCategory", failureCategory);
                        context.addMetadata("securityDecisionFallbackReason", "LLM_EXECUTION_FAILED");
                        context.addMetadata("securityDecisionRawExecutionFailureClass", error.getClass().getName());
                        context.addMetadata("securityDecisionRawExecutionFailureMessage", SensitiveValueSanitizer.sanitizeText(error.getMessage()));
                        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, "");
                        return Mono.just("");
                    });
        }

        if (finalTargetType != null && structuredOutputMode != StructuredOutputMode.LEGACY_RAW) {
            context.addMetadata("entityExecutionAttempted", true);
            context.addMetadata("rawExecutionAttempted", false);
            context.addMetadata("structuredOutputMode", structuredOutputMode.name());
            context.addMetadata("structuredOutputPolicy", structuredOutputPolicy.name());
            return preparePrompt(context)
                    .flatMap(prompt -> executeEntity(prompt, request, context, finalTargetType, structuredOutputMode, structuredOutputPolicy)
                            .doOnSuccess(response -> {
                                context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                                context.addMetadata("structuredOutputComplete", true);
                                context.addMetadata("entityExecutionSucceeded", true);
                            })
                            .cast(Object.class)
                            .onErrorResume(error -> {
                                context.addMetadata("entityExecutionSucceeded", false);
                                context.addMetadata("structuredOutputComplete", false);
                                context.addMetadata("structuredOutputFailureCategory", categorizeFailure(error).name());
                                if (!structuredOutputPolicy.allowsRawFallback()) {
                                    log.error("[PIPELINE-STEP] Structured output execution failed and raw fallback is forbidden. Request: {}",
                                            request.getRequestId(), error);
                                    return Mono.error(asStructuredOutputExecutionException(error));
                                }
                                log.error("[PIPELINE-STEP] Structured output execution failed. Attempting raw String fallback. Request: {}", request.getRequestId(), error);
                                context.addMetadata("rawExecutionAttempted", true);
                                context.addMetadata("structuredOutputMode", StructuredOutputMode.LEGACY_RAW.name());
                                return executeRaw(prompt, request, context)
                                        .switchIfEmpty(Mono.error(new IllegalStateException("LLM raw fallback returned empty Mono")))
                                        .doOnSuccess(rawResponse -> context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, rawResponse))
                                        .cast(Object.class);
                            }))
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .doFinally(signalType -> {
                        long elapsedMs = System.currentTimeMillis() - stepStartTime;
                        context.addMetadata("llmExecutionLatencyMs", elapsedMs);
                        context.addMetadata("llmStepMs", elapsedMs);
                        log.info("[PIPELINE-STEP] LLM execution completed - Request: {}, Signal: {}, Duration: {}ms",
                                request.getRequestId(), signalType, elapsedMs);
                    })
                    .onErrorResume(Mono::error);
        }

        return preparePrompt(context)
                .flatMap(prompt -> {
                    context.addMetadata("entityExecutionAttempted", false);
                    context.addMetadata("structuredOutputComplete", false);
                    context.addMetadata("rawExecutionAttempted", true);
                    context.addMetadata("structuredOutputMode", StructuredOutputMode.LEGACY_RAW.name());
                    return executeRaw(prompt, request, context);
                })
                .doOnSuccess(response -> context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response))
                .cast(Object.class)
                .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                .doFinally(signalType -> {
                        long elapsedMs = System.currentTimeMillis() - stepStartTime;
                        context.addMetadata("llmExecutionLatencyMs", elapsedMs);
                        context.addMetadata("llmStepMs", elapsedMs);
                        log.info("[PIPELINE-STEP] LLM execution completed - Request: {}, Signal: {}, Duration: {}ms",
                                request.getRequestId(), signalType, elapsedMs);
                    })
                .onErrorResume(error -> {
                    log.error("[PIPELINE-STEP] LLM execution failed. Request: {}", request.getRequestId());
                    return Mono.error(error);
                });
    }

    private String rawExecutionFailureCategory(PipelineExecutionContext context, Throwable error) {
        String explicit = firstNonBlankMetadata(
                context,
                "providerCallFailureCategory",
                "decisionFailureCategory",
                "structuredOutputFailureCategory",
                "securityDecisionParseFailureCategory");
        if (explicit != null && explicit.toUpperCase().contains("TIMEOUT")) {
            return explicit.toUpperCase();
        }
        if (isTimeout(error)) {
            return "TIMEOUT";
        }
        // A response that reached the model but broke the decision contract is not a model outage.
        StructuredOutputFailureCategory structuredCategory = structuredOutputFailureCategory(error);
        return structuredCategory != null ? structuredCategory.name() : "MODEL_UNAVAILABLE";
    }

    private StructuredOutputFailureCategory structuredOutputFailureCategory(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof StructuredOutputExecutionException structured && structured.getCategory() != null) {
                return structured.getCategory();
            }
            current = current.getCause();
        }
        return null;
    }

    private String firstNonBlankMetadata(PipelineExecutionContext context, String... keys) {
        if (context == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = context.getMetadata(key, Object.class);
            if (value != null && !value.toString().isBlank()) {
                return value.toString().trim();
            }
        }
        return null;
    }
    private boolean isTimeout(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof TimeoutException) {
                return true;
            }
            String name = current.getClass().getName();
            String message = current.getMessage();
            if ((name != null && name.toLowerCase().contains("timeout"))
                    || (message != null && message.toLowerCase().contains("timeout"))
                    || (message != null && message.toLowerCase().contains("timed out"))) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    public <T extends DomainContext> Flux<String> executeStreaming(AIRequest<T> request, PipelineExecutionContext context) {
        return preparePrompt(context)
                .flatMapMany(prompt -> executeStream(prompt, request, context))
                .doOnError(error -> log.error("[PIPELINE-STEP] Streaming execution failed. Request: {}", request.getRequestId(), error));
    }

    protected Mono<Prompt> preparePrompt(PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            PromptGenerationResult promptResult = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PROMPT_GENERATION, PromptGenerationResult.class);

            if (promptResult == null || promptResult.getPrompt() == null) {
                throw new IllegalStateException("Prompt not found in context. Skipping LLM execution.");
            }
            return promptResult.getPrompt();
        }).onErrorResume(IllegalStateException.class, e -> {
            log.error("[PIPELINE-STEP] {}", e.getMessage());
            return Mono.error(e);
        });
    }

    private <T extends DomainContext> Mono<?> executeEntity(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType,
            StructuredOutputMode structuredOutputMode,
            StructuredOutputPolicy structuredOutputPolicy) {
        ExecutionContext executionContext = buildExecutionContext(prompt, request, context, targetType, structuredOutputMode, structuredOutputPolicy);
        if (llmClient instanceof LLMOperations operations) {
            return operations.executeEntity(executionContext, targetType)
                    .doOnSuccess(response -> syncExecutionMetadata(context, executionContext))
                    .doOnError(error -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.entity(prompt, targetType);
    }

    private <T extends DomainContext> Mono<String> executeSecurityDecisionRawGuarded(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        ExecutionContext executionContext = buildExecutionContext(
                prompt,
                request,
                context,
                null,
                StructuredOutputMode.LEGACY_RAW,
                StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        // W4-5 (plan 7): the minimum action rules are checked here only in enforce mode; observe mode records them.
        SecurityDecisionRawOutputContractInspector.MinimumActionCheck ruleCheck = minimumActionCheck(request);
        // W4-8: a v20 decision is checked on the facts its prompt was drawn from.
        SecurityDecisionRawOutputContractInspector.V20Check v20Check = v20Check(request, context);
        return executeRaw(executionContext, context)
                .flatMap(rawResponse -> {
                    Inspection initialCheck = rawOutputContractInspector.inspect(
                            rawResponse,
                            prompt,
                            request.getRequestId(),
                            "initial",
                            ruleCheck,
                            v20Check);
                    if (!initialCheck.requiresRetry()) {
                        return Mono.just(rawResponse);
                    }
                    recordInitialSecurityDecisionFailure(context, initialCheck, rawResponse);
                    // W4-5: an answer cut at the output limit is asked again with twice the limit; any other violation is
                    // retried once with the answer and what was wrong with it, after the same prompt.
                    boolean truncated = truncatedAtTheOutputLimit(executionContext);
                    String retryReason = truncated ? OUTPUT_TRUNCATED : initialCheck.retryReason();
                    context.addMetadata("securityDecisionOutputRetryAttempted", true);
                    context.addMetadata("securityDecisionOutputRetryReason", retryReason);
                    ExecutionContext retryContext = buildExecutionContext(
                            truncated ? prompt : correctivePrompt(prompt, rawResponse, retryReason),
                            request,
                            context,
                            null,
                            StructuredOutputMode.LEGACY_RAW,
                            StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
                    if (truncated && executionContext.getMaxTokens() != null) {
                        retryContext.setMaxTokens(executionContext.getMaxTokens() * 2);
                    }
                    return executeRaw(retryContext, context)
                            .map(retryResponse -> {
                                Inspection retryCheck = rawOutputContractInspector.inspect(
                                        retryResponse,
                                        prompt,
                                        request.getRequestId(),
                                        "retry",
                                        ruleCheck,
                                        v20Check);
                                boolean succeeded = !retryCheck.requiresRetry();
                                context.addMetadata("securityDecisionOutputRetrySucceeded", succeeded);
                                // N-OUT-1 (G1-2): the retry answer as it came and the action read from it.
                                context.addMetadata("securityDecisionRetryRawOutput", retryResponse);
                                if (!retryCheck.parsingFallback() && retryCheck.response() != null) {
                                    context.addMetadata("securityDecisionRetryAction", retryCheck.response().getAction());
                                }
                                if (!succeeded) {
                                    context.addMetadata(
                                            "securityDecisionOutputRetryFailureReason",
                                            retryCheck.retryReason());
                                    // N-OUT-1 (G1-1): the parser takes this fallback for the empty answer.
                                    context.addMetadata(
                                            SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION,
                                            SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                                                    retryCheck.retryReason()));
                                    throw new StructuredOutputExecutionException(
                                            StructuredOutputFailureCategory.VALIDATION_FAILED,
                                            "Security decision output violated the response contract after retry: "
                                                    + retryCheck.retryReason());
                                }
                                return retryResponse;
                            })
                            .doOnError(error -> context.addMetadata("securityDecisionOutputRetrySucceeded", false));
                });
    }

    /**
     * The minimum action rule check of a security decision in enforce mode: the decision facts of the canonical context
     * the prompt was drawn from (on the event), its resource, and the settings the strategy put on the request; null in
     * observe mode or when the facts are not there.
     */
    private static SecurityDecisionRawOutputContractInspector.MinimumActionCheck minimumActionCheck(AIRequest<?> request) {
        String mode = request != null ? request.getParameter("minimumActionMode", String.class) : null;
        if (!"ENFORCE".equalsIgnoreCase(mode != null ? mode.trim() : "")
                || !(request.getContext() instanceof SecurityDecisionContext decision)
                || decision.getSecurityEvent() == null || decision.getSecurityEvent().getMetadata() == null
                || !(decision.getSecurityEvent().getMetadata().get("sealedEvidence.canonicalContext")
                        instanceof CanonicalSecurityContext canonical)
                || canonical.getDecisionFacts() == null) {
            return null;
        }
        MinimumActionRules.Settings settings = request.getParameter("minimumActionSettings", MinimumActionRules.Settings.class);
        CanonicalSecurityContext.Resource resource = canonical.getResource();
        return new SecurityDecisionRawOutputContractInspector.MinimumActionCheck(canonical.getDecisionFacts(),
                resource != null ? resource.getResourceClass() : null, resource != null ? resource.getActionFamily() : null,
                settings != null ? settings : MinimumActionRules.Settings.DEFAULTS);
    }

    /**
     * W4-8: the inputs of the v20 checks: the canonical context the prompt was drawn from (on the event), the user
     * prompt it drew and the rule settings on the request; null when the prompt is not the v20 dictionary blocks.
     */
    private static SecurityDecisionRawOutputContractInspector.V20Check v20Check(AIRequest<?> request,
                                                                             PipelineExecutionContext context) {
        PromptGenerationResult generated = context.getStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION, PromptGenerationResult.class);
        PromptExecutionMetadata metadata = generated != null ? generated.getPromptExecutionMetadata() : null;
        Object layout = metadata != null && metadata.supplementalMetadata() != null
                ? metadata.supplementalMetadata().get(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION) : null;
        if (!SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V20.equals(layout)
                || !(request.getContext() instanceof SecurityDecisionContext decision)
                || decision.getSecurityEvent() == null || decision.getSecurityEvent().getMetadata() == null
                || !(decision.getSecurityEvent().getMetadata().get("sealedEvidence.canonicalContext")
                        instanceof CanonicalSecurityContext canonical)) {
            return null;
        }
        MinimumActionRules.Settings settings = request.getParameter("minimumActionSettings", MinimumActionRules.Settings.class);
        return new SecurityDecisionRawOutputContractInspector.V20Check(canonical, generated.getUserPrompt(),
                settings != null ? settings : MinimumActionRules.Settings.DEFAULTS);
    }

    /** Whether the provider ended the answer at the output limit (OpenAI {@code length}, Anthropic {@code max_tokens}). */
    private static boolean truncatedAtTheOutputLimit(ExecutionContext executionContext) {
        Object reason = executionContext.getMetadata().get("providerFinishReason");
        String text = reason != null ? reason.toString().trim().toLowerCase(Locale.ROOT) : "";
        return "length".equals(text) || "max_tokens".equals(text);
    }

    /**
     * W4-5: the prompt again with the answer it got and what was wrong with it, so the one retry corrects that answer
     * instead of drawing a new one blind.
     */
    static Prompt correctivePrompt(Prompt prompt, String previousAnswer, String violation) {
        List<Message> messages = new ArrayList<>(prompt.getInstructions());
        messages.add(new AssistantMessage(previousAnswer != null ? previousAnswer : ""));
        messages.add(new UserMessage("The previous answer was rejected (" + violation + "). Answer again with one JSON"
                + " object that follows the output contract and the rules, with the action and reasons the facts in the"
                + " prompt support."));
        return new Prompt(messages, prompt.getOptions());
    }

    private void recordInitialSecurityDecisionFailure(
            PipelineExecutionContext context,
            Inspection check,
            String rawResponse) {
        context.addMetadata("securityDecisionInitialRawOutputHash", check.rawOutputHash());
        // N-OUT-1 (G1-2): the first answer as it came.
        context.addMetadata("securityDecisionInitialRawOutput", rawResponse);
        context.addMetadata("securityDecisionInitialRawOutputLength", check.rawOutputLength());
        context.addMetadata("securityDecisionInitialParseFailureCategory", check.parseFailureCategory());
        if (check.parsingFallback()) {
            context.addMetadata("securityDecisionInitialFallbackAction", check.response().getAction());
            context.addMetadata("securityDecisionInitialFallbackReason", check.parseFailureCategory());
        }
        if (check.semanticViolation() != null) {
            context.addMetadata("securityDecisionInitialSemanticViolation", check.semanticViolation());
            context.addMetadata("securityDecisionInitialProposedAction", check.response().getAction());
        }
    }
    private <T extends DomainContext> Mono<String> executeRaw(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        ExecutionContext executionContext = buildExecutionContext(
                prompt,
                request,
                context,
                null,
                StructuredOutputMode.LEGACY_RAW,
                StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        return executeRaw(executionContext, context);
    }

    private Mono<String> executeRaw(
            ExecutionContext executionContext,
            PipelineExecutionContext context) {
        if (llmClient instanceof LLMOperations operations) {
            return operations.execute(executionContext)
                    .doOnSuccess(response -> syncExecutionMetadata(context, executionContext))
                    .doOnError(error -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.call(executionContext.getPrompt());
    }
    private <T extends DomainContext> Flux<String> executeStream(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        ExecutionContext executionContext = buildExecutionContext(
                prompt,
                request,
                context,
                null,
                StructuredOutputMode.LEGACY_RAW,
                StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        if (llmClient instanceof LLMOperations operations) {
            return operations.stream(executionContext)
                    .doOnNext(chunk -> syncExecutionMetadata(context, executionContext))
                    .doOnError(error -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.stream(prompt);
    }

    private <T extends DomainContext> ExecutionContext buildExecutionContext(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType,
            StructuredOutputMode structuredOutputMode,
            StructuredOutputPolicy structuredOutputPolicy) {
        ExecutionContext executionContext = ExecutionContext.from(prompt);
        executionContext.setRequestId(request != null ? request.getRequestId() : null);
        LlmObservationContext observation = SecurityDecisionObservationContextResolver.resolve(request);
        if (observation != null) {
            executionContext.addMetadata(LlmObservationContext.CONTEXT_KEY, observation);
        }
        boolean securityDecisionTarget = isSecurityDecisionTarget(request, context, targetType);

        ResolvedValue<String> requestedModel = resolveStringParameter(request, context,
                "preferredModel",
                "requestedModelId",
                "runtimeModelId");
        ResolvedValue<Double> temperature = resolveDoubleParameter(request, context,
                "temperature",
                "runtimeTemperature");
        ResolvedValue<Double> topP = resolveDoubleParameter(request, context,
                "topP",
                "runtimeTopP");
        ResolvedValue<Integer> seed = resolveIntegerParameter(request, context,
                "seed",
                "runtimeSeed");
        ResolvedValue<Integer> maxTokens = resolveIntegerParameter(request, context,
                "maxTokens",
                "runtimeMaxTokens");
        ResolvedValue<String> openAiReasoningEffort = resolveStringParameter(request, context,
                "openAiReasoningEffort",
                "runtimeOpenAiReasoningEffort");
        ResolvedValue<String> openAiVerbosity = resolveStringParameter(request, context,
                "openAiVerbosity",
                "runtimeOpenAiVerbosity");
        ResolvedValue<String> promptCacheKey = resolveStringParameter(request, context, "promptCacheKey");
        ResolvedValue<String> outputSchema = resolveStringParameter(request, context, ExecutionContext.OUTPUT_SCHEMA);
        ResolvedValue<Boolean> disableRetries = resolveBooleanParameter(request, context, "disableRetries");
        ResolvedValue<Boolean> disableOllamaThinking = resolveBooleanParameter(request, context, "disableOllamaThinking");
        ResolvedValue<String> boundaryMode = resolveStringParameter(request, context, "decisionBoundaryMode");
        if (securityDecisionTarget) {
            // P3-EXTRA-9: the platform's model call limit, set by the strategy and never by the request.
            ResolvedValue<Integer> callTimeoutMs =
                    resolveIntegerParameter(request, context, "platformSecurityDecisionCallTimeoutMs");
            if (callTimeoutMs != null && callTimeoutMs.value() > 0) {
                executionContext.addMetadata(ExecutionContext.CALL_TIMEOUT_MS, callTimeoutMs.value().longValue());
            }
            requestedModel = nullIfSecurityOverride(context, "preferredModel", requestedModel);
            temperature = nullIfSecurityOverride(context, "temperature", temperature);
            topP = nullIfSecurityOverride(context, "topP", topP);
            seed = nullIfSecurityOverride(context, "seed", seed);
            maxTokens = resolveTrustedSecurityMaxTokens(request, context, maxTokens);
            disableRetries = nullIfSecurityOverride(context, "disableRetries", disableRetries);
            disableOllamaThinking = nullIfSecurityOverride(context, "disableOllamaThinking", disableOllamaThinking);
            boundaryMode = nullIfSecurityOverride(context, "decisionBoundaryMode", boundaryMode);
        }

        ResolvedValue<String> boundaryReasoningEffort = securityDecisionTarget ? null : openAiReasoningEffort;
        ResolvedValue<String> boundaryVerbosity = securityDecisionTarget ? null : openAiVerbosity;
        if (boundaryMode == null && hasAnyRuntimeOverrides(requestedModel, temperature, topP, seed, maxTokens, boundaryReasoningEffort, boundaryVerbosity, disableRetries, disableOllamaThinking)) {
            boundaryMode = new ResolvedValue<>("RUNTIME_MODEL_SELECTION", "derived.runtimeSelection");
        }

        if (requestedModel != null) {
            executionContext.setPreferredModel(requestedModel.value());
            recordMetadata(context, executionContext, "requestedModelId", requestedModel.value());
            recordMetadata(context, executionContext, "preferredModel", requestedModel.value());
            recordMetadata(context, executionContext, "runtimeModelId", requestedModel.value());
            recordMetadata(context, executionContext, "requestedModelSourceKey", requestedModel.sourceKey());
        }
        if (temperature != null) {
            executionContext.setTemperature(temperature.value());
            recordMetadata(context, executionContext, "temperature", temperature.value());
        }
        if (topP != null) {
            executionContext.setTopP(topP.value());
            recordMetadata(context, executionContext, "topP", topP.value());
        }
        if (seed != null) {
            executionContext.setSeed(seed.value());
            recordMetadata(context, executionContext, "seed", seed.value());
        }
        if (securityDecisionTarget) {
            // N-OUT-1 (G1-8): the tier of the analysing layer, set after the runtime selection check since it is not a
            // request's override.
            ResolvedValue<Integer> platformTier = resolveIntegerParameter(request, context, "platformAnalysisTier");
            if (platformTier != null) {
                executionContext.setTier(platformTier.value());
                recordMetadata(context, executionContext, "analysisTier", platformTier.value());
            }
            // W4-6: the platform's determinism settings, set after the runtime selection check since they are not a
            // request's override; the options factory records the ones the provider does not take.
            ResolvedValue<Double> platformTemperature =
                    resolveDoubleParameter(request, context, "platformDeterminismTemperature");
            ResolvedValue<Integer> platformSeed = resolveIntegerParameter(request, context, "platformDeterminismSeed");
            if (platformTemperature != null) {
                executionContext.setTemperature(platformTemperature.value());
                recordMetadata(context, executionContext, "platformDeterminismTemperature", platformTemperature.value());
            }
            if (platformSeed != null) {
                executionContext.setSeed(platformSeed.value());
                recordMetadata(context, executionContext, "platformDeterminismSeed", platformSeed.value());
            }
        }
        if (maxTokens != null) {
            executionContext.setMaxTokens(maxTokens.value());
            recordMetadata(context, executionContext, "maxTokens", maxTokens.value());
        }
        if (openAiReasoningEffort != null) {
            recordMetadata(context, executionContext, "openAiReasoningEffort", openAiReasoningEffort.value());
        }
        if (openAiVerbosity != null) {
            recordMetadata(context, executionContext, "openAiVerbosity", openAiVerbosity.value());
        }
        if (promptCacheKey != null) {
            executionContext.addMetadata("promptCacheKey", promptCacheKey.value());
        }
        // W4-2: the output schema the provider enforces when its options support structured output.
        if (outputSchema != null) {
            executionContext.addMetadata(ExecutionContext.OUTPUT_SCHEMA, outputSchema.value());
        }
        if (disableRetries != null) {
            executionContext.addMetadata("disableRetries", disableRetries.value());
            recordMetadata(context, executionContext, "disableRetries", disableRetries.value());
        }
        if (disableOllamaThinking != null) {
            executionContext.addMetadata("disableOllamaThinking", disableOllamaThinking.value());
            recordMetadata(context, executionContext, "disableOllamaThinking", disableOllamaThinking.value());
        }
        if (boundaryMode != null) {
            recordMetadata(context, executionContext, "decisionBoundaryMode", boundaryMode.value());
        }
        if (structuredOutputMode != null) {
            recordMetadata(context, executionContext, "structuredOutputMode", structuredOutputMode.name());
        }
        if (structuredOutputPolicy != null) {
            recordMetadata(context, executionContext, "structuredOutputPolicy", structuredOutputPolicy.name());
        }
        recordMetadata(context, executionContext, "structuredOutputProviderFamily",
                context != null ? context.getMetadata("structuredOutputProviderFamily", Object.class) : null);
        recordMetadata(context, executionContext, "structuredOutputNativeSupported",
                context != null ? context.getMetadata("structuredOutputNativeSupported", Object.class) : null);
        recordMetadata(context, executionContext, "structuredOutputValidationAdvisorSupported",
                context != null ? context.getMetadata("structuredOutputValidationAdvisorSupported", Object.class) : null);
        recordMetadata(context, executionContext, "structuredOutputCapabilitySource",
                context != null ? context.getMetadata("structuredOutputCapabilitySource", Object.class) : null);
        if (targetType != null && structuredOutputMode != StructuredOutputMode.LEGACY_RAW) {
            ResolvedValue<Integer> validationAttempts = resolveIntegerParameter(request, context, "structuredOutputValidationMaxAttempts");
            int maxRepeatAttempts = validationAttempts != null
                    ? Math.max(0, validationAttempts.value())
                    : 1;
            if (structuredOutputMode == StructuredOutputMode.VALIDATED_CONVERTER) {
                executionContext.addAdvisor(StructuredOutputValidationAdvisor.builder()
                        .outputType(targetType)
                        .maxRepeatAttempts(maxRepeatAttempts)
                        .build());
            }
            recordMetadata(context, executionContext, "structuredOutputValidationMaxAttempts", maxRepeatAttempts);
        }
        return executionContext;
    }

    private <T extends DomainContext> ResolvedValue<Integer> resolveTrustedSecurityMaxTokens(
            AIRequest<T> request,
            PipelineExecutionContext context,
            ResolvedValue<Integer> blockedRuntimeMaxTokens) {
        recordIgnoredSecurityOverride(context, "maxTokens", blockedRuntimeMaxTokens);
        ResolvedValue<Integer> platformMaxTokens =
                resolveIntegerParameter(request, context, "platformSecurityDecisionMaxTokens");
        if (platformMaxTokens != null) {
            return new ResolvedValue<>(platformMaxTokens.value(), "platformSecurityDecisionMaxTokens");
        }
        return null;
    }

    private <T> ResolvedValue<T> nullIfSecurityOverride(
            PipelineExecutionContext context,
            String canonicalKey,
            ResolvedValue<T> value) {
        recordIgnoredSecurityOverride(context, canonicalKey, value);
        return null;
    }

    private void recordIgnoredSecurityOverride(
            PipelineExecutionContext context,
            String canonicalKey,
            ResolvedValue<?> value) {
        if (context == null || value == null) {
            return;
        }
        context.addMetadata("securityDecisionRuntimeOverrideIgnored", true);
        context.addMetadata("securityDecisionRuntimeOverrideIgnored." + canonicalKey, value.sourceKey());
    }

    private <T extends DomainContext> StructuredOutputMode resolveStructuredOutputMode(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType,
            StructuredOutputCapability capability) {
        if (targetType == null) {
            return StructuredOutputMode.LEGACY_RAW;
        }
        Object configuredMode = resolveRawParameter(request, context, "structuredOutputMode");
        if (configuredMode != null) {
            StructuredOutputMode resolved = StructuredOutputMode.fromValue(configuredMode, StructuredOutputMode.VALIDATED_CONVERTER);
            return resolved;
        }
        ResolvedValue<Boolean> nativeStructuredEnabled = resolveBooleanParameter(request, context, "nativeStructuredOutputEnabled");
        if (nativeStructuredEnabled != null
                && !nativeStructuredEnabled.value()
                && capability.nativeStructuredSupported()) {
            return StructuredOutputMode.VALIDATED_CONVERTER;
        }
        return capability.resolvePreferredMode();
    }

    private <T extends DomainContext> StructuredOutputCapability resolveStructuredOutputCapability(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType) {
        String modelHint = null;
        // A security decision runs on the configured model, so no request names its model.
        ResolvedValue<String> requestedModel = isSecurityDecisionTarget(targetType)
                ? null
                : resolveStringParameter(request, context,
                        "requestedModelId",
                        "preferredModel",
                        "runtimeModelId");
        if (requestedModel != null) {
            modelHint = requestedModel.value();
        }
        String providerHint = null;
        ResolvedValue<String> providerValue = resolveStringParameter(request, context,
                "selectedModelProvider",
                "providerResponseModel");
        if (providerValue != null) {
            providerHint = providerValue.value();
        }
        return structuredOutputCapabilityRegistry.resolve(modelHint, providerHint, targetType != null);
    }

    private <T extends DomainContext> boolean isSecurityDecisionTarget(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType) {
        if (isSecurityDecisionTarget(targetType)) {
            return true;
        }
        if (context != null) {
            if (isSecurityDecisionTarget(context.getMetadata("aiGenerationType", Class.class))) {
                return true;
            }
            if (isSecurityDecisionTarget(context.getMetadata("targetResponseType", Class.class))) {
                return true;
            }
        }
        return request != null && isSecurityDecisionTarget(request.getParameter("responseType", Class.class));
    }

    private boolean isSecurityDecisionTarget(Class<?> targetType) {
        return SecurityDecisionResponseLite.class.equals(targetType)
                || SecurityDecisionResponse.class.equals(targetType);
    }

    private <T extends DomainContext> StructuredOutputPolicy resolveStructuredOutputPolicy(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType) {
        Object configuredPolicy = resolveRawParameter(request, context, "structuredOutputPolicy");
        if (configuredPolicy != null) {
            return StructuredOutputPolicy.fromValue(configuredPolicy, StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        }
        return targetType != null
                ? StructuredOutputPolicy.ALLOW_RAW_FALLBACK
                : StructuredOutputPolicy.ALLOW_RAW_FALLBACK;
    }

    private StructuredOutputFailureCategory categorizeFailure(Throwable error) {
        if (error instanceof StructuredOutputExecutionException structuredException) {
            return structuredException.getCategory();
        }
        return StructuredOutputFailureCategory.ENTITY_EXECUTION_FAILED;
    }

    private StructuredOutputExecutionException asStructuredOutputExecutionException(Throwable error) {
        if (error instanceof StructuredOutputExecutionException structuredException) {
            return structuredException;
        }
        return new StructuredOutputExecutionException(
                StructuredOutputFailureCategory.ENTITY_EXECUTION_FAILED,
                "Structured output execution failed",
                error);
    }

    private boolean hasAnyRuntimeOverrides(Object... values) {
        for (Object value : values) {
            if (value != null) {
                return true;
            }
        }
        return false;
    }

    private void syncExecutionMetadata(PipelineExecutionContext context, ExecutionContext executionContext) {
        if (context == null || executionContext == null || executionContext.getMetadata() == null) {
            return;
        }
        for (String key : EXECUTION_METADATA_KEYS) {
            Object value = executionContext.getMetadata().get(key);
            if (value != null) {
                context.addMetadata(key, value);
            }
        }
        reconcileActualPromptBudgetTelemetry(context);
        recordObservedPromptTokenUsage(context);
    }

    private void reconcileActualPromptBudgetTelemetry(PipelineExecutionContext context) {
        Number actualPromptTokens = context.getMetadata("actualPromptTokens", Number.class);
        Number budgetMaxInputTokens = context.getMetadata("budgetMaxInputTokens", Number.class);
        Boolean usageAvailable = context.getMetadata("actualTokenUsageAvailable", Boolean.class);
        if (actualPromptTokens == null || budgetMaxInputTokens == null || !Boolean.TRUE.equals(usageAvailable)) {
            return;
        }
        int actualInput = Math.max(0, actualPromptTokens.intValue());
        int maxInput = Math.max(1, budgetMaxInputTokens.intValue());
        int remaining = maxInput - actualInput;
        double utilizationRate = actualInput / (double) maxInput;
        context.addMetadata("actualPromptBudgetRemainingTokens", remaining);
        context.addMetadata("actualPromptBudgetUtilizationRate", utilizationRate);
        context.addMetadata("actualPromptBudgetExceeded", actualInput > maxInput);
        context.addMetadata("actualPromptUsageSource", "PROVIDER_USAGE");
    }

    private void recordObservedPromptTokenUsage(PipelineExecutionContext context) {
        Number actualPromptTokens = context.getMetadata("actualPromptTokens", Number.class);
        Boolean usageAvailable = context.getMetadata("actualTokenUsageAvailable", Boolean.class);
        if (actualPromptTokens == null || !Boolean.TRUE.equals(usageAvailable)) {
            return;
        }
        Number promptLength = context.getMetadata("llmTotalPromptLength", Number.class);
        if (promptLength == null) {
            promptLength = context.getMetadata("totalPromptLength", Number.class);
        }
        if (promptLength == null || promptLength.intValue() <= 0) {
            return;
        }
        for (String modelHint : new String[] {
                context.getMetadata("requestedModelId", String.class),
                context.getMetadata("preferredModel", String.class),
                context.getMetadata("runtimeModelId", String.class),
                context.getMetadata("selectedModelId", String.class),
                context.getMetadata("providerResponseModel", String.class)}) {
            ObservedPromptTokenUsageRegistry.recordObservation(
                    modelHint,
                    promptLength.intValue(),
                    actualPromptTokens.intValue());
        }
    }

    private void recordMetadata(
            PipelineExecutionContext context,
            ExecutionContext executionContext,
            String key,
            Object value) {
        if (context != null && key != null && value != null) {
            context.addMetadata(key, value);
        }
        if (executionContext != null && key != null && value != null) {
            executionContext.addMetadata(key, value);
        }
    }

    private <T extends DomainContext> Object resolveRawParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String key) {
        if (request != null && request.getParameters().containsKey(key)) {
            return request.getParameters().get(key);
        }
        return context != null ? context.getMetadata(key, Object.class) : null;
    }

    private <T extends DomainContext> ResolvedValue<String> resolveStringParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof String text && !text.isBlank()) {
                return new ResolvedValue<>(text.trim(), key);
            }
            if (value != null) {
                String text = String.valueOf(value).trim();
                if (!text.isEmpty()) {
                    return new ResolvedValue<>(text, key);
                }
            }
        }
        return null;
    }

    private <T extends DomainContext> ResolvedValue<Double> resolveDoubleParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof Double number) {
                return new ResolvedValue<>(number, key);
            }
            if (value instanceof Number number) {
                return new ResolvedValue<>(number.doubleValue(), key);
            }
            if (value instanceof String text && !text.isBlank()) {
                try {
                    return new ResolvedValue<>(Double.parseDouble(text.trim()), key);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private <T extends DomainContext> ResolvedValue<Integer> resolveIntegerParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof Integer number) {
                return new ResolvedValue<>(number, key);
            }
            if (value instanceof Number number) {
                return new ResolvedValue<>(number.intValue(), key);
            }
            if (value instanceof String text && !text.isBlank()) {
                try {
                    return new ResolvedValue<>(Integer.parseInt(text.trim()), key);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private <T extends DomainContext> ResolvedValue<Boolean> resolveBooleanParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof Boolean bool) {
                return new ResolvedValue<>(bool, key);
            }
            if (value instanceof String text && !text.isBlank()) {
                return new ResolvedValue<>(Boolean.parseBoolean(text.trim()), key);
            }
        }
        return null;
    }

    private void logError(String requestId, Throwable error, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.error("[PIPELINE-STEP] LLM execution failed - Request: {}, Duration: {}ms, Error: {}",
                requestId, totalTime, error.getMessage());
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.LLM_EXECUTION;
    }

    public LLMClient getLlmClient() {
        return llmClient;
    }

    @Override
    public int getOrder() {
        return 4;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return llmClient != null;
    }

    private record ResolvedValue<T>(T value, String sourceKey) {
    }
}

