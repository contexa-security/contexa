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
package io.contexa.contexacore.autonomous.learning.evidence;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LearningContextEvidenceAssemblerTest {

    private final LearningContextEvidenceAssembler assembler = new LearningContextEvidenceAssembler();

    @Test
    @DisplayName("assembler should derive no-data baseline when no typed personal baseline evidence exists")
    void assemblerShouldDeriveNoDataBaselineWithoutTypedEvidence() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();

        LearningContextEvidence evidence = assembler.assemble(
                "alice",
                SecurityEvent.builder().userId("alice").build(),
                null,
                behaviorAnalysis,
                List.of());

        assertThat(evidence.personalBaseline().status()).isEqualTo(BaselineEvidenceStatus.NO_DATA);
        assertThat(evidence.personalBaseline().summary()).isEmpty();
        assertThat(evidence.personalBaseline().diagnostic()).isEmpty();
    }

    @Test
    @DisplayName("assembler should preserve explicit typed unavailable baseline evidence")
    void assemblerShouldPreserveExplicitTypedUnavailableBaselineEvidence() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                false,
                false,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "",
                BaselineEvidenceStatus.SERVICE_UNAVAILABLE,
                "baseline service unavailable"));

        LearningContextEvidence evidence = assembler.assemble(
                "alice",
                SecurityEvent.builder().userId("alice").build(),
                null,
                behaviorAnalysis,
                List.of());

        assertThat(evidence.personalBaseline().status()).isEqualTo(BaselineEvidenceStatus.SERVICE_UNAVAILABLE);
        assertThat(evidence.personalBaseline().diagnostic()).isEqualTo("baseline service unavailable");
    }

    @Test
    @DisplayName("assembler should normalize requested resource ids into comparable path families and combination carry facts")
    void assemblerShouldNormalizeRequestedResourceIdsIntoComparablePathFamilies() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                true,
                true,
                20L,
                0.91d,
                List.of("CORPORATE"),
                List.of("23"),
                List.of("6"),
                List.of("Chrome/120"),
                List.of("Windows"),
                List.of("/admin/api/security-test/sensitive/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("SENSITIVE"),
                "personal baseline established",
                BaselineEvidenceStatus.AVAILABLE,
                ""));

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .sourceIp("10.10.0.20")
                .build();
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/self-sensitive-1");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("deviceBrowser", "Chrome");
        event.addMetadata("deviceBrowserVersion", "120");
        event.addMetadata("deviceOs", "Windows");
        event.addMetadata("authMethod", "UsernamePasswordAuthenticationToken");

        LearningContextEvidence evidence = assembler.assemble(
                "alice",
                event,
                null,
                behaviorAnalysis,
                List.of(new Document(
                        "behavior summary",
                        Map.of(
                                "documentType", "behavior",
                                "userId", "alice",
                                "requestedResourceId", "/admin/api/security-test/sensitive/baseline-3",
                                "resourceSensitivity", "HIGH",
                                "hour", "23",
                                "dayOfWeek", "6",
                                "deviceBrowser", "Chrome/120",
                                "deviceOs", "Windows",
                                "authenticationType", "PASSWORD",
                                "actionFamily", "READ"))));

        assertThat(evidence.personalRetrievedEvidence()).hasSize(1);
        assertThat(evidence.personalRetrievedEvidence().get(0).pathFamily())
                .isEqualTo("/admin/api/security-test/sensitive/*");
        assertThat(evidence.carryRequiredFacts())
                .contains(
                        "WorkProfileEvidenceState",
                        "ObservedPatternEvidenceScope",
                        "HistoricalComparableScope",
                        "CurrentRequestCombinationEvidenceScope",
                        "CurrentRequestCombinationSeenCount",
                        "CurrentRequestCombinationComparedDimensions",
                        "CurrentRequestClosestObservedOverlap",
                        "StrongestCurrentRequestCombinationDelta",
                        "CurrentRequestCombinationSummary",
                        "ObservedComparableCombination1");
    }
}
