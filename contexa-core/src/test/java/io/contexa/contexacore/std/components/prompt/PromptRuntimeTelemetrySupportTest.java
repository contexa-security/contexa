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

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptRuntimeTelemetrySupportTest {

    /**
     * W3-8: the provider prompt cache key and whether it was sent travel with the decision's telemetry, and a new run
     * clears them first so a key of an earlier layer is not kept.
     */
    @Test
    void theTelemetryCarriesThePromptCacheKeyAndWhetherItWasSent() {
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(Map.of(
                "promptCacheKey", "contexa-0123456789abcdef",
                "promptCacheKeyApplied", true,
                "cachedPromptTokens", 3072));

        assertThat(telemetry)
                .containsEntry("promptCacheKey", "contexa-0123456789abcdef")
                .containsEntry("promptCacheKeyApplied", true)
                .containsEntry("cachedPromptTokens", 3072);
        assertThat(PromptRuntimeTelemetrySupport.clearableRuntimeTelemetryKeys())
                .contains("promptCacheKey", "promptCacheKeyApplied");
    }

    /**
     * N-OUT-1 (G1-2): the record keys carry the re-call and the model's first verdict; the raw answers travel on a path
     * of their own (not through the record keys the forwarding mappers read), and the seal's model output block names
     * both with the effective settings.
     */
    @Test
    void theModelOutputIsRecordedAndItsRawAnswersTravelApart() {
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(Map.of(
                "securityDecisionOutputRetryAttempted", true,
                "securityDecisionOutputRetryReason", "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH",
                "securityDecisionInitialProposedAction", "CHALLENGE",
                "securityDecisionContractFallbackAction", "ALLOW",
                "providerFinishReason", "stop",
                "securityDecisionRawOutput", "{\"action\":\"ALLOW\"}"));

        assertThat(telemetry)
                .containsEntry("securityDecisionOutputRetryAttempted", true)
                .containsEntry("securityDecisionOutputRetryReason", "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH")
                .containsEntry("securityDecisionInitialProposedAction", "CHALLENGE")
                .containsEntry("securityDecisionContractFallbackAction", "ALLOW")
                .containsEntry("providerFinishReason", "stop")
                .doesNotContainKey("securityDecisionRawOutput");
        assertThat(PromptRuntimeTelemetrySupport.modelOutputTextKeys()).containsExactly(
                "securityDecisionRawOutput", "securityDecisionInitialRawOutput", "securityDecisionRetryRawOutput");
        assertThat(PromptRuntimeTelemetrySupport.modelOutputRecordKeys())
                .contains("securityDecisionInitialProposedAction", "securityDecisionOutputRetryAttempted",
                        "securityDecisionRetryAction", "securityDecisionRawOutput", "securityDecisionInitialRawOutput",
                        "securityDecisionRetryRawOutput", "providerFinishReason", "maxTokens", "providerReasoningEffort",
                        "providerResponseModel");
    }

    /** W4-7 (inventory 6 bundle 10): the completeness reasons travel with the decision. */
    @Test
    void theTelemetryCarriesTheCompletenessReasons() {
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(Map.of(
                "promptEvidenceCompleteness", "PARTIAL",
                "promptEvidenceCompletenessReasons", List.of("not-integrated: ClientSignals")));

        assertThat(telemetry).containsEntry("promptEvidenceCompletenessReasons", List.of("not-integrated: ClientSignals"));
    }

    /**
     * W4-6: every decision records the model version the provider answered with, the reasoning effort sent and the
     * determinism settings; a new run clears them. The host's reasoning effort option is not cleared.
     */
    @Test
    void theTelemetryCarriesTheModelVersionTheReasoningEffortAndTheDeterminism() {
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(Map.of(
                "providerResponseModel", "gpt-6-luna-2026-09-30",
                "providerReasoningEffort", "low",
                "platformDeterminismTemperature", 0.0d,
                "platformDeterminismSeed", 1,
                "determinismNotApplied", List.of("temperature")));

        assertThat(telemetry)
                .containsEntry("providerResponseModel", "gpt-6-luna-2026-09-30")
                .containsEntry("providerReasoningEffort", "low")
                .containsEntry("platformDeterminismTemperature", 0.0d)
                .containsEntry("platformDeterminismSeed", 1)
                .containsEntry("determinismNotApplied", List.of("temperature"));
        assertThat(PromptRuntimeTelemetrySupport.clearableRuntimeTelemetryKeys())
                .contains("providerReasoningEffort", "platformDeterminismTemperature", "platformDeterminismSeed",
                        "determinismNotApplied")
                .doesNotContain("openAiReasoningEffort");
    }
}
