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
            "disableOllamaThinking",
            "officialVerificationDecisionBoundaryMode",
            "officialVerificationPinnedModelId",
            "officialVerificationTemperature",
            "officialVerificationTopP",
            "officialVerificationSeed",
            "officialVerificationMaxTokens",
            "officialVerificationDisableRetries",
            "officialVerificationDisableOllamaThinking"
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
            "officialVerificationDecisionBoundaryMode",
            "officialVerificationPinnedModelId",
            "officialVerificationTemperature",
            "officialVerificationTopP",
            "officialVerificationSeed",
            "officialVerificationMaxTokens",
            "officialVerificationDisableRetries",
            "officialVerificationDisableOllamaThinking",
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
            "providerCallMs",
            "providerCallTimeoutMs",
            "providerCallExceededTimeout",
            "providerCallFailed",
            "providerCallFailureCategory",
            "providerCallFailureClass",
            "providerCallFailureMessage",
            "openAiCallMs",
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

    private PromptRuntimeTelemetrySupport() {
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
                telemetry.put(key, value);
            }
        }
        return telemetry;
    }
}
