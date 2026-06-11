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
package io.contexa.contexacore.autonomous.saas.learning.prompt;

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptPresentationExperimentServiceTest {

    private final PromptPresentationExperimentService service =
            new PromptPresentationExperimentService(new PromptPresentationObservationFactory());

    @Test
    void aggregatesWhitelistedPresentationPatternObservationsWithoutUsingPromptText() {
        LocalDateTime now = LocalDateTime.of(2026, 4, 8, 10, 15);
        PromptContextAuditPayload firstAudit = PromptContextAuditPayload.builder()
                .auditId("audit-1")
                .correlationId("corr-1")
                .promptKey("security-decision")
                .templateKey("standard")
                .promptVersion("v3")
                .systemPrompt("DO NOT LEAK")
                .userPrompt("Analyze the user")
                .promptHash("hash-a")
                .systemPromptHash("sys-hash-a")
                .userPromptHash("usr-hash-a")
                .retrievalPurpose("threat-decision")
                .deniedDocumentCount(2)
                .promptRuntimeTelemetryLinked(true)
                .promptRuntimeTelemetry(Map.of(
                        "promptTransformationMode", "CONDENSED",
                        "promptCompressionApplied", true,
                        "promptSectionSet", List.of("summary", "evidence", "policy"),
                        "omittedSections", List.of("narrative"),
                        "promptEvidenceCompleteness", "PARTIAL",
                        "promptOmissionCount", 1,
                        "promptBudgetUtilizationRate", 0.82d,
                        "systemPrompt", "must-not-be-read",
                        "promptHash", "must-not-be-read"))
                .forwardedAt(now)
                .build();
        PromptContextAuditPayload secondAudit = PromptContextAuditPayload.builder()
                .auditId("audit-2")
                .correlationId("corr-2")
                .promptKey("security-decision")
                .templateKey("standard")
                .promptVersion("v3")
                .systemPrompt("DO NOT LEAK 2")
                .userPrompt("Analyze the user 2")
                .promptHash("hash-b")
                .systemPromptHash("sys-hash-b")
                .userPromptHash("usr-hash-b")
                .retrievalPurpose("threat-decision")
                .deniedDocumentCount(0)
                .promptRuntimeTelemetryLinked(true)
                .promptRuntimeTelemetry(Map.of(
                        "promptTransformationMode", "CONDENSED",
                        "promptCompressionApplied", true,
                        "promptSectionSet", List.of("summary", "evidence", "policy"),
                        "omittedSections", List.of("narrative"),
                        "promptEvidenceCompleteness", "PARTIAL",
                        "promptOmissionCount", 1,
                        "promptBudgetUtilizationRate", 0.58d))
                .forwardedAt(now.plusMinutes(2))
                .build();

        DecisionFeedbackPayload firstFeedback = DecisionFeedbackPayload.builder()
                .feedbackId("fb-1")
                .correlationId("corr-1")
                .feedbackType("OPERATOR_REVIEW_FALSE_POSITIVE")
                .adminAction("OVERRIDE_TO_ALLOW")
                .originalAction("CHALLENGE")
                .overriddenAction("ALLOW")
                .feedbackTimestamp(now.plusMinutes(1))
                .build();
        DecisionFeedbackPayload secondFeedback = DecisionFeedbackPayload.builder()
                .feedbackId("fb-2")
                .correlationId("corr-2")
                .feedbackType("OPERATOR_REVIEW")
                .adminAction("CONFIRM_BLOCK")
                .originalAction("BLOCK")
                .overriddenAction("BLOCK")
                .feedbackTimestamp(now.plusMinutes(3))
                .build();

        ThreatOutcomePayload firstOutcome = ThreatOutcomePayload.builder()
                .outcomeId("out-1")
                .correlationId("corr-1")
                .outcomeType("FALSE_POSITIVE_CASE")
                .finalDisposition("BENIGN_CONFIRMED")
                .finalAction("ALLOW")
                .resolutionSource("OPERATOR_REVIEW")
                .outcomeTimestamp(now.plusMinutes(1))
                .build();
        ThreatOutcomePayload secondOutcome = ThreatOutcomePayload.builder()
                .outcomeId("out-2")
                .correlationId("corr-2")
                .outcomeType("CONFIRMED_ATTACK")
                .finalDisposition("CONFIRMED_ATTACK")
                .finalAction("BLOCK")
                .resolutionSource("OPERATOR_REVIEW")
                .outcomeTimestamp(now.plusMinutes(4))
                .build();

        ModelPerformanceTelemetryPayload telemetry = ModelPerformanceTelemetryPayload.builder()
                .telemetryId("tele-1")
                .period(LocalDate.of(2026, 4, 8))
                .layer1EscalationRate(0.21d)
                .blockRate(0.09d)
                .challengeRate(0.16d)
                .generatedAt(now.plusHours(1))
                .build();

        PromptPresentationExperimentPortfolio portfolio = service.evaluate(new PromptPresentationExperimentInput(
                List.of(firstAudit, secondAudit),
                List.of(firstFeedback, secondFeedback),
                List.of(firstOutcome, secondOutcome),
                List.of(telemetry)));

        assertThat(portfolio.promptAuditCount()).isEqualTo(2L);
        assertThat(portfolio.experimentObservationCount()).isEqualTo(2L);
        assertThat(portfolio.unclassifiedAuditCount()).isZero();
        assertThat(portfolio.results()).hasSize(1);

        PromptPresentationExperimentResult result = portfolio.results().get(0);
        assertThat(result.patternProfile().patternKey()).contains("prompt=security-decision", "template=standard", "transform=CONDENSED");
        assertThat(result.patternProfile().patternKey()).doesNotContain("DO NOT LEAK", "Analyze the user", "hash-a", "hash-b");
        assertThat(result.sampleSize()).isEqualTo(2L);
        assertThat(result.operatorReviewedOutcomeCount()).isEqualTo(2L);
        assertThat(result.reviewerDisagreementCount()).isEqualTo(1L);
        assertThat(result.falsePositiveOutcomeCount()).isEqualTo(1L);
        assertThat(result.falseNegativeOutcomeCount()).isZero();
        assertThat(result.omissionLinkedCount()).isEqualTo(2L);
        assertThat(result.telemetryLinkedCount()).isEqualTo(2L);
        assertThat(result.averageDeniedContextCount()).isEqualTo(1.0d);
        assertThat(result.averageOmittedSectionCount()).isEqualTo(1.0d);
        assertThat(result.averagePromptBudgetUtilizationRate()).isEqualTo(0.70d);
        assertThat(result.policyFacts()).anyMatch(text -> text.contains("exclude raw prompt text"));
        assertThat(result.policyFacts()).anyMatch(text -> text.contains("prompt hashes"));
        assertThat(result.evidenceFacts()).noneMatch(text -> text.contains("DO NOT LEAK") || text.contains("hash-a") || text.contains("hash-b"));
    }

    @Test
    void countsAuditsWithoutPresentationSignalsAsUnclassified() {
        PromptContextAuditPayload audit = PromptContextAuditPayload.builder()
                .auditId("audit-plain")
                .correlationId("corr-plain")
                .systemPrompt("should-not-appear")
                .userPrompt("should-not-appear")
                .promptHash("hash-plain")
                .forwardedAt(LocalDateTime.of(2026, 4, 8, 12, 0))
                .build();

        PromptPresentationExperimentPortfolio portfolio = service.evaluate(new PromptPresentationExperimentInput(
                List.of(audit),
                List.of(),
                List.of(),
                List.of()));

        assertThat(portfolio.promptAuditCount()).isEqualTo(1L);
        assertThat(portfolio.experimentObservationCount()).isZero();
        assertThat(portfolio.unclassifiedAuditCount()).isEqualTo(1L);
        assertThat(portfolio.results()).isEmpty();
    }
}