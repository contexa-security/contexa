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
package io.contexa.contexacore.hcad.evaluation;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HcadOutcomeClassifierTest {

    @Test
    @DisplayName("HCAD-triggered risky LLM decision should be true positive")
    void classifyHcadTriggered_riskyDecision_shouldBeTruePositive() {
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .proposedAction(ZeroTrustAction.CHALLENGE.name())
                .build();

        assertThat(HcadOutcomeClassifier.classifyHcadTriggered(result, ZeroTrustAction.ALLOW))
                .isEqualTo(HcadOutcomeClassifier.TRUE_POSITIVE);
    }

    @Test
    @DisplayName("HCAD-triggered allow LLM decision should be false positive")
    void classifyHcadTriggered_allowDecision_shouldBeFalsePositive() {
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .build();

        assertThat(HcadOutcomeClassifier.classifyHcadTriggered(result, ZeroTrustAction.ALLOW))
                .isEqualTo(HcadOutcomeClassifier.FALSE_POSITIVE);
    }

    @Test
    @DisplayName("HCAD observation with risky Protectable LLM decision should be false negative")
    void classifyHcadObservation_riskyDecision_shouldBeFalseNegative() {
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .build();

        assertThat(HcadOutcomeClassifier.classifyHcadObservation(result, ZeroTrustAction.BLOCK))
                .isEqualTo(HcadOutcomeClassifier.FALSE_NEGATIVE);
    }

    @Test
    @DisplayName("technical fallback should be unknown")
    void classify_fallback_shouldBeUnknown() {
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .technicalFallbackApplied(true)
                .llmDecisionPresent(false)
                .build();

        assertThat(HcadOutcomeClassifier.classifyHcadTriggered(result, ZeroTrustAction.BLOCK))
                .isEqualTo(HcadOutcomeClassifier.UNKNOWN);
    }
}
