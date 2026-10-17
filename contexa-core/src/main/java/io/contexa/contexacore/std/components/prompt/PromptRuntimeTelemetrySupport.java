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
package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacore.util.SensitiveValueSanitizer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PromptRuntimeTelemetrySupport {

    private static final List<String> RUNTIME_SELECTION_OPTION_KEYS = List.of(
            "decisionBoundaryMode",
            "requestedModelId",
            "requestedModelSourceKey",
            "preferredModel",
            "temperature",
            "topP",
            "seed",
            "maxTokens",
            "disableRetries",
            "disableOllamaThinking"
    );

    private static final List<String> RUNTIME_TELEMETRY_KEYS = List.of(
            "promptKey",
            "templateKey",
            "promptVersion",
            "contractVersion",
            "promptReleaseStatus",
            "promptOwner",
            "promptReleaseApprovalReference",
            "promptEvaluationBaselineReference",
            "promptRollbackVersion",
            "promptChangeSummary",
            "promptSupportedModelProfiles",
            "promptTemplateClass",
            "budgetProfile",
            "budgetProfileDescription",
            "budgetMaxInputTokens",
            "budgetSystemReserveTokens",
            "budgetUserReserveTokens",
            "budgetOutputReserveTokens",
            "budgetExpansionAllowed",
            "promptTokenEstimator",
            "estimatedSystemTokens",
            "estimatedUserTokens",
            "estimatedTotalTokens",
            "promptBudgetRemainingTokens",
            "promptBudgetUtilizationRate",
            "promptBudgetExceeded",
            "promptBudgetEnforcementMode",
            "promptCompressionApplied",
            "promptTransformationMode",
            "promptRawTruthParity",
            "promptCompressionOperationCount",
            "promptCompressionSavedCharacters",
            "promptCompressionSavedEstimatedTokens",
            "promptCompressionLedger",
            "promptSourceContextFieldCount",
            "promptSourceContextTraversalDepthLimitCount",
            "promptSourceContextTraversalCycleCount",
            "promptSourceContextTraversalErrorCount",
            "promptSourceContextExhaustive",
            "promptSourceContextFailureCount",
            "promptFieldStateCount",
            "promptBlockingFieldStateCount",
            "promptRawUserFieldCount",
            "promptFinalUserFieldCount",
            "promptUserFieldDiffCount",
            "promptUserFieldLossCount",
            "promptUserFieldChangedCount",
            "promptUserFieldAddedCount",
            "promptUserFieldCompactedMarkerCount",
            "promptUserFieldTruncatedMarkerCount",
            "promptSectionSet",
            "omittedSections",
            "omissionLedger",
            "promptEvidenceCompleteness",
            "promptEvidenceCompletenessReasons",
            "learningPersonalBaselineEstablished",
            "learningSupportingBaselineAvailable",
            "supportingBaselineUsed",
            "personalRetrievedDocCount",
            "supportingRetrievedDocCount",
            "supportingComparableCount",
            "learningCarryRequiredFacts",
            "learningCarryMissingFacts",
            "renderedDeltaCount",
            "strongestLearningDelta",
            "historicalComparableCount",
            "historicalComparableScope",
            "observedPatternEvidenceScope",
            "currentRequestCombinationSeenCount",
            "currentRequestCombinationEvidenceScope",
            "currentRequestCombinationComparedDimensions",
            "currentRequestClosestObservedOverlap",
            "strongestCurrentRequestCombinationDelta",
            "currentRequestCombinationSummary",
            "observedComparableCombination1",
            "learningSectionPresent",
            "supportingLearningSectionPresent",
            "renderedRequestSnapshot",
            "renderedLearningSnapshot",
            "renderedLabelMatrix",
            "compactedLineCountBySection",
            "promptContractViolations",
            "promptContractViolationCount",
            "promptOmissionCount",
            "promptHash",
            "systemPromptHash",
            "userPromptHash",
            "staticPromptPrefixHash",
            "promptCacheEligible",
            "promptCacheHit",
            "cachedPromptTokens",
            "promptCacheKey",
            "promptCacheKeyApplied",
            "rawPromptHash",
            "rawSystemPromptHash",
            "rawUserPromptHash",
            "structuredOutputMode",
            "structuredOutputPolicy",
            "structuredOutputProviderFamily",
            "structuredOutputNativeSupported",
            "structuredOutputValidationAdvisorSupported",
            "structuredOutputCapabilitySource",
            "entityExecutionAttempted",
            "entityExecutionSucceeded",
            "rawExecutionAttempted",
            "rawExecutionSucceeded",
            "structuredOutputFailureCategory",
            "securityDecisionParsingMode",
            "securityDecisionCoreFieldsPresent",
            "securityDecisionParsingFallbackApplied",
            "securityDecisionFallbackApplied",
            "securityDecisionFallbackAction",
            "securityDecisionFallbackReason",
            "securityDecisionOutputRepairApplied",
            "securityDecisionOutputRepairFields",
            "securityDecisionParseFailureCategory",
            "securityDecisionRawOutputHash",
            "securityDecisionRawOutputLength",
            "securityDecisionRawExecutionFailureClass",
            "securityDecisionRawExecutionFailureMessage",
            "syntheticSecurityDecisionApplied",
            "llmDecisionPresent",
            "technicalFallbackApplied",
            "technicalFallbackCategory",
            "technicalFallbackReason",
            "technicalFallbackAction",
            "providerResponseId",
            "providerResponseModel",
            // N-OUT-1 (G1-2): the model's first verdict and the re-call.
            "securityDecisionInitialProposedAction",
            "securityDecisionInitialSemanticViolation",
            "securityDecisionInitialParseFailureCategory",
            "securityDecisionInitialFallbackAction",
            "securityDecisionOutputRetryAttempted",
            "securityDecisionOutputRetryReason",
            "securityDecisionOutputRetrySucceeded",
            "securityDecisionOutputRetryFailureReason",
            "securityDecisionRetryAction",
            "securityDecisionContractFallbackAction",
            "providerFinishReason",
            // W4-6: the reasoning effort sent and the determinism settings, recorded with every decision.
            "providerReasoningEffort",
            "platformDeterminismTemperature",
            "platformDeterminismSeed",
            "determinismNotApplied",
            "actualPromptTokens",
            "actualCompletionTokens",
            "actualTotalTokens",
            "actualTokenUsageAvailable",
            "actualPromptBudgetRemainingTokens",
            "actualPromptBudgetUtilizationRate",
            "actualPromptBudgetExceeded",
            "actualPromptUsageSource",
            "requestedModelId",
            "requestedModelSourceKey",
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
            "disableRetries",
            "disableOllamaThinking",
            "decisionBoundaryMode",
            "systemPromptLength",
            "userPromptLength",
            "totalPromptLength",
            "rawSystemPromptLength",
            "rawUserPromptLength",
            "rawTotalPromptLength",
            "llmSystemPromptLength",
            "llmUserPromptLength",
            "llmTotalPromptLength",
            "promptGeneratedAtEpochMs",
            "promptBuildLatencyMs",
            "contextRetrievalMs",
            "preprocessingMs",
            "pipelinePromptGenerationMs",
            "llmExecutionLatencyMs",
            "llmStepMs",
            "responseParsingMs",
            "securityDecisionParseMs",
            "postprocessingLatencyMs",
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
            "providerResponseMetadataMs",
            "responseExtractMs",
            "layer1SessionContextMs",
            "layer1RagSearchMs",
            "layer1BehaviorAnalysisMs",
            "layer1PromptPreparationMs",
            "layer1PipelineBlockMs",
            "layer1ResponseValidateMs",
            "layer1PostProcessMs",
            "layer1TotalMs",
            "processingStrategyMs",
            "processingStrategyMode"
    );

    private static final List<String> CLEARABLE_RUNTIME_TELEMETRY_KEYS = RUNTIME_TELEMETRY_KEYS.stream()
            .filter(key -> !RUNTIME_SELECTION_OPTION_KEYS.contains(key))
            .toList();

    /**
     * N-OUT-1 (G1-2): the model's raw answers. They reach the event on a path of their own, like the prompt texts, and
     * not through the record keys the forwarding mappers read.
     */
    private static final List<String> MODEL_OUTPUT_TEXT_KEYS = List.of(
            "securityDecisionRawOutput",
            "securityDecisionInitialRawOutput",
            "securityDecisionRetryRawOutput"
    );

    /**
     * N-OUT-1 (G1-2, G2-8): the model output the seal keeps with the decision: the first verdict, the re-call, the raw
     * answers and the effective settings the call ran with.
     */
    private static final List<String> MODEL_OUTPUT_RECORD_KEYS = List.of(
            "securityDecisionInitialProposedAction",
            "securityDecisionInitialSemanticViolation",
            "securityDecisionInitialParseFailureCategory",
            "securityDecisionInitialFallbackAction",
            "securityDecisionOutputRetryAttempted",
            "securityDecisionOutputRetryReason",
            "securityDecisionOutputRetrySucceeded",
            "securityDecisionOutputRetryFailureReason",
            "securityDecisionRetryAction",
            "securityDecisionContractFallbackAction",
            "providerFinishReason",
            "securityDecisionRawOutput",
            "securityDecisionInitialRawOutput",
            "securityDecisionRetryRawOutput",
            "maxTokens",
            "providerReasoningEffort",
            "providerResponseModel",
            "platformDeterminismTemperature",
            "platformDeterminismSeed",
            "determinismNotApplied"
    );

    /**
     * N-L2-1: the event metadata key of the first user prompt drawn for the event; the Layer2 second pass reads it
     * (W3-9), and the cold path drops it once the analysis ends.
     */
    public static final String FIRST_PASS_USER_PROMPT = "firstPassUserPrompt";

    /**
     * N-RSN-1: the event metadata key of the reason codes the first pass's model gave; a Layer2 second pass that keeps
     * the first verdict without a model call keeps them (W3-9), and the cold path drops them once the analysis ends.
     */
    public static final String FIRST_PASS_REASON_CODES = "firstPassReasonCodes";

    /**
     * W6-6: the event metadata key of the model call stages of a decision: one entry per layer that called the model,
     * kept when the next layer clears its telemetry.
     */
    public static final String MODEL_CALL_STAGES = "modelCallStages";

    /**
     * N-OUT-3: the key of a decision's output retries in the order they were asked: why each was asked, whether its
     * answer kept the response contract and, when that answer did not, what it broke. A pipeline run lists its own; the
     * event lists those of every layer, each naming its layer, and keeps them when the next layer clears its telemetry,
     * as it keeps the model call stages, while the single retry fields still hold the last layer's retry only. The
     * list travels on a path of its own, not through the record keys the forwarding mappers read, and the seal keeps
     * it with the model output.
     */
    public static final String OUTPUT_RETRIES = "securityDecisionOutputRetries";

    /**
     * W6-6: adds the stage the layer just ran to the event's model call stages: the layer, the prompt hashes it sent
     * and the model output it got (the first answer, a corrective retry with its reason, the answer it kept). The texts
     * are not copied again; the seal keeps the applied stage's prompt once.
     */
    public static void appendModelCallStage(Map<String, Object> eventMetadata, String layer) {
        if (eventMetadata == null) {
            return;
        }
        Map<String, Object> stage = new LinkedHashMap<>();
        stage.put("layer", layer);
        for (String key : List.of("userPromptHash", "systemPromptHash")) {
            Object value = eventMetadata.get(key);
            if (value != null) {
                stage.put(key, value);
            }
        }
        for (String key : MODEL_OUTPUT_RECORD_KEYS) {
            Object value = eventMetadata.get(key);
            if (value != null) {
                stage.put(key, value);
            }
        }
        List<Object> stages = new ArrayList<>();
        if (eventMetadata.get(MODEL_CALL_STAGES) instanceof List<?> earlier) {
            stages.addAll(earlier);
        }
        stages.add(stage);
        eventMetadata.put(MODEL_CALL_STAGES, List.copyOf(stages));
    }

    /**
     * N-OUT-3: adds the retries of the run a layer just finished to the event's retries, after those of the layers
     * before it and in their order, each naming the layer; a run without a retry leaves them as they are.
     */
    public static void appendOutputRetries(Map<String, Object> eventMetadata, String layer, Object runRetries) {
        if (eventMetadata == null || !(runRetries instanceof List<?> retries) || retries.isEmpty()) {
            return;
        }
        List<Object> all = new ArrayList<>();
        if (eventMetadata.get(OUTPUT_RETRIES) instanceof List<?> earlier) {
            all.addAll(earlier);
        }
        for (Object retry : retries) {
            if (retry instanceof Map<?, ?> entry) {
                Map<String, Object> named = new LinkedHashMap<>();
                named.put("layer", layer);
                entry.forEach((key, value) -> named.putIfAbsent(String.valueOf(key), value));
                all.add(named);
            }
        }
        eventMetadata.put(OUTPUT_RETRIES, List.copyOf(all));
    }

    /**
     * N-OUT-3: the run's retries with one more at the end: why it was asked, whether its answer kept the contract and,
     * when that answer did not, what it broke (a retry whose call failed names nothing).
     */
    public static List<Object> withOutputRetry(Object runRetries, String reason, boolean succeeded,
                                               String failureReason) {
        List<Object> retries = new ArrayList<>();
        if (runRetries instanceof List<?> earlier) {
            retries.addAll(earlier);
        }
        Map<String, Object> retry = new LinkedHashMap<>();
        retry.put("reason", reason);
        retry.put("succeeded", succeeded);
        if (failureReason != null) {
            retry.put("failureReason", failureReason);
        }
        retries.add(retry);
        return List.copyOf(retries);
    }

    private PromptRuntimeTelemetrySupport() {
    }

    public static List<String> modelOutputTextKeys() {
        return MODEL_OUTPUT_TEXT_KEYS;
    }

    public static List<String> modelOutputRecordKeys() {
        return MODEL_OUTPUT_RECORD_KEYS;
    }

    public static List<String> runtimeTelemetryKeys() {
        return RUNTIME_TELEMETRY_KEYS;
    }

    public static List<String> runtimeSelectionOptionKeys() {
        return RUNTIME_SELECTION_OPTION_KEYS;
    }

    public static List<String> clearableRuntimeTelemetryKeys() {
        return CLEARABLE_RUNTIME_TELEMETRY_KEYS;
    }

    public static Map<String, Object> extractRuntimeTelemetry(Map<String, Object> metadata) {
        Map<String, Object> telemetry = new LinkedHashMap<>();
        if (metadata == null || metadata.isEmpty()) {
            return telemetry;
        }
        for (String key : RUNTIME_TELEMETRY_KEYS) {
            Object value = metadata.get(key);
            if (value != null) {
                telemetry.put(key, SensitiveValueSanitizer.sanitizeValueForKey(key, value));
            }
        }
        return telemetry;
    }
}

