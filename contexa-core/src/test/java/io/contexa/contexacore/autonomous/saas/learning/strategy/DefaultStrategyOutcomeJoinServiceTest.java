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
package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultStrategyOutcomeJoinServiceTest {

    @Test
    @DisplayName("join service should correlate feedback outcome prompt telemetry and campaign into one observation")
    void shouldCorrelateInputsIntoSingleObservation() {
        DefaultStrategyOutcomeJoinService service = new DefaultStrategyOutcomeJoinService();
        LocalDateTime anchorTime = LocalDateTime.of(2026, 4, 8, 10, 30, 0);

        DecisionFeedbackPayload feedback = DecisionFeedbackPayload.builder()
                .feedbackId("fb-1")
                .correlationId("corr-1")
                .feedbackType("FALSE_NEGATIVE")
                .adminAction("APPROVED_BLOCK")
                .aiAnalysisLevel(2)
                .originalAction("ALLOW")
                .overriddenAction("BLOCK")
                .feedbackTimestamp(anchorTime.minusMinutes(5))
                .attributes(Map.of("requestPath", "/admin/export/report"))
                .build();
        ThreatOutcomePayload outcome = ThreatOutcomePayload.builder()
                .outcomeId("out-1")
                .correlationId("corr-1")
                .outcomeType("CONFIRMED_ATTACK")
                .finalDisposition("MALICIOUS")
                .originalAction("ALLOW")
                .finalAction("BLOCK")
                .outcomeTimestamp(anchorTime)
                .attributes(Map.of(
                        "requestPath", "/admin/export/report",
                        "failedLoginAttempts", 4,
                        "isImpossibleTravel", true,
                        "isNewDevice", true,
                        "isSensitiveResource", true,
                        "threatKnowledgeSignalKeys", List.of("failed_login_burst", "impossible_travel"),
                        "geoCountry", "KR"))
                .build();
        PromptContextAuditPayload promptAudit = PromptContextAuditPayload.builder()
                .auditId("audit-1")
                .correlationId("corr-1")
                .retrievalPurpose("security-decision")
                .contextFingerprint("fp-1")
                .requestedDocumentCount(6)
                .allowedDocumentCount(4)
                .deniedDocumentCount(2)
                .deniedReasons(List.of("policy_denied"))
                .contexts(List.of(
                        PromptContextAuditPayload.ContextItem.builder()
                                .contextType("xai_report")
                                .sourceType("xai_memory")
                                .artifactId("xai-1")
                                .includedInPrompt(true)
                                .build()))
                .promptKey("security-decision")
                .templateKey("std-template")
                .promptVersion("v3")
                .resourceId("report-77")
                .requestPath("/admin/export/report")
                .promptRuntimeTelemetryLinked(true)
                .promptRuntimeTelemetryLayer("LAYER2")
                .promptRuntimeTelemetry(Map.of(
                        "selectedModelId", "gpt-5.4",
                        "promptEvidenceCompleteness", "RICH",
                        "promptSectionSet", List.of("bridge", "approval"),
                        "promptOmissionCount", 1))
                .forwardedAt(anchorTime.minusMinutes(1))
                .build();
        ModelPerformanceTelemetryPayload telemetry = ModelPerformanceTelemetryPayload.builder()
                .telemetryId("telemetry-1")
                .period(LocalDate.of(2026, 4, 8))
                .layer1EscalationRate(0.42d)
                .blockRate(0.15d)
                .challengeRate(0.21d)
                .generatedAt(anchorTime.plusMinutes(3))
                .build();
        StrategyCampaignObservation campaignObservation = new StrategyCampaignObservation(
                "corr-1",
                "campaign_signal",
                "account_takeover",
                "KR",
                List.of("Campaign fact A"),
                anchorTime.minusMinutes(2));

        List<StrategyLearningObservation> observations = service.join(new DetectionStrategyLearningInput(
                List.of(feedback),
                List.of(outcome),
                List.of(promptAudit),
                List.of(telemetry),
                List.of(campaignObservation)));

        assertThat(observations).hasSize(1);
        StrategyLearningObservation observation = observations.get(0);
        assertThat(observation.correlationId()).isEqualTo("corr-1");
        assertThat(observation.feedbackType()).isEqualTo("FALSE_NEGATIVE");
        assertThat(observation.outcomeType()).isEqualTo("CONFIRMED_ATTACK");
        assertThat(observation.finalDisposition()).isEqualTo("MALICIOUS");
        assertThat(observation.aiAnalysisLevel()).isEqualTo(2);
        assertThat(observation.promptAuditLinked()).isTrue();
        assertThat(observation.deniedContextCount()).isEqualTo(2);
        assertThat(observation.telemetryLinked()).isTrue();
        assertThat(observation.campaignObserved()).isTrue();
        assertThat(observation.layer1EscalationRate()).isEqualTo(0.42d);
        assertThat(observation.blockRate()).isEqualTo(0.15d);
        assertThat(observation.challengeRate()).isEqualTo(0.21d);
        assertThat(observation.signalKeys()).containsExactlyInAnyOrder(
                "failed_login_burst",
                "impossible_travel",
                "campaign_signal");
        assertThat(observation.strategySignals())
                .containsEntry("requestPath", "/admin/export/report")
                .containsEntry("pathCategory", "sensitive_data")
                .containsEntry("resourceId", "report-77")
                .containsEntry("retrievalPurpose", "security-decision")
                .containsEntry("xaiLinked", true)
                .containsEntry("failedLoginAttempts", 4)
                .containsEntry("isImpossibleTravel", true)
                .containsEntry("isNewDevice", true)
                .containsEntry("geoCountry", "KR");
        assertThat((Map<String, Object>) observation.strategySignals().get("promptRuntimeTelemetry"))
                .containsEntry("selectedModelId", "gpt-5.4")
                .containsEntry("promptEvidenceCompleteness", "RICH");
        assertThat(observation.evidenceFacts()).anyMatch(fact -> fact.contains("Prompt runtime telemetry"));
        assertThat(observation.evidenceFacts()).anyMatch(fact -> fact.contains("Campaign account_takeover"));
        assertThat(observation.evidenceFacts()).anyMatch(fact -> fact.contains("XAI-linked evidence"));
    }

    @Test
    @DisplayName("join service should create fallback correlation units when correlation ids are absent")
    void shouldCreateFallbackCorrelationUnitsWhenCorrelationIdsAreAbsent() {
        DefaultStrategyOutcomeJoinService service = new DefaultStrategyOutcomeJoinService();

        DecisionFeedbackPayload feedback = DecisionFeedbackPayload.builder()
                .feedbackId("fb-2")
                .feedbackType("CORRECT")
                .adminAction("REVIEWED")
                .feedbackTimestamp(LocalDateTime.of(2026, 4, 8, 9, 0, 0))
                .build();
        PromptContextAuditPayload promptAudit = PromptContextAuditPayload.builder()
                .auditId("audit-2")
                .retrievalPurpose("security-decision")
                .allowedDocumentCount(1)
                .deniedDocumentCount(0)
                .forwardedAt(LocalDateTime.of(2026, 4, 8, 9, 5, 0))
                .build();

        List<StrategyLearningObservation> observations = service.join(new DetectionStrategyLearningInput(
                List.of(feedback),
                List.of(),
                List.of(promptAudit),
                List.of(),
                List.of()));

        assertThat(observations).hasSize(2);
        assertThat(observations).extracting(StrategyLearningObservation::correlationId)
                .containsExactlyInAnyOrder("feedback:fb-2", "prompt-audit:audit-2");
    }

    @Test
    @DisplayName("join service should select telemetry closest to observation date")
    void shouldSelectClosestTelemetryPeriod() {
        DefaultStrategyOutcomeJoinService service = new DefaultStrategyOutcomeJoinService();
        LocalDateTime feedbackTime = LocalDateTime.of(2026, 4, 8, 11, 0, 0);

        DecisionFeedbackPayload feedback = DecisionFeedbackPayload.builder()
                .feedbackId("fb-3")
                .correlationId("corr-telemetry")
                .feedbackType("CORRECT")
                .adminAction("REVIEWED")
                .feedbackTimestamp(feedbackTime)
                .build();
        ModelPerformanceTelemetryPayload olderTelemetry = ModelPerformanceTelemetryPayload.builder()
                .telemetryId("telemetry-old")
                .period(LocalDate.of(2026, 3, 29))
                .layer1EscalationRate(0.05d)
                .blockRate(0.01d)
                .challengeRate(0.02d)
                .generatedAt(feedbackTime.minusDays(10))
                .build();
        ModelPerformanceTelemetryPayload nearestTelemetry = ModelPerformanceTelemetryPayload.builder()
                .telemetryId("telemetry-near")
                .period(LocalDate.of(2026, 4, 8))
                .layer1EscalationRate(0.33d)
                .blockRate(0.11d)
                .challengeRate(0.12d)
                .generatedAt(feedbackTime.plusHours(1))
                .build();

        StrategyLearningObservation observation = service.join(new DetectionStrategyLearningInput(
                List.of(feedback),
                List.of(),
                List.of(),
                List.of(olderTelemetry, nearestTelemetry),
                List.of())).get(0);

        assertThat(observation.telemetryLinked()).isTrue();
        assertThat(observation.layer1EscalationRate()).isEqualTo(0.33d);
        assertThat(observation.blockRate()).isEqualTo(0.11d);
        assertThat(observation.challengeRate()).isEqualTo(0.12d);
    }
}
