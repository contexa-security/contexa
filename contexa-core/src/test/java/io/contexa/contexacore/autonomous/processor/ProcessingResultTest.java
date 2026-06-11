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
package io.contexa.contexacore.autonomous.processor;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProcessingResultTest {

    @Test
    void resolveAuditScoresPreferExplicitAuditFields() {
        ProcessingResult result = ProcessingResult.builder()
                .riskScore(0.10)
                .confidence(0.20)
                .llmAuditRiskScore(0.91)
                .llmAuditConfidence(0.87)
                .build();

        assertThat(result.resolveAuditRiskScore()).isEqualTo(0.91);
        assertThat(result.resolveAuditConfidence()).isEqualTo(0.87);
    }

    @Test
    void resolveAuditScoresIgnoreLegacyFieldsWhenAuditFieldsAreMissing() {
        ProcessingResult result = ProcessingResult.builder()
                .riskScore(0.33)
                .confidence(0.44)
                .build();

        assertThat(result.resolveAuditRiskScore()).isNull();
        assertThat(result.resolveAuditConfidence()).isNull();
    }

    @Test
    void successFactoryStoresAuditRiskScoreWithoutLegacyRiskScore() {
        ProcessingResult result = ProcessingResult.success(
                ProcessingResult.ProcessingPath.COLD_PATH,
                0.72);

        assertThat(result.getRiskScore()).isNull();
        assertThat(result.getLlmAuditRiskScore()).isEqualTo(0.72);
    }

    @Test
    void processingResultPreservesProposedAndEnforcedDecisionSeparately() {
        ProcessingResult result = ProcessingResult.builder()
                .action("CHALLENGE")
                .proposedAction("ALLOW")
                .confidence(0.54)
                .llmAuditConfidence(0.91)
                .build();

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getProposedAction()).isEqualTo("ALLOW");
        assertThat(result.getConfidence()).isEqualTo(0.54);
        assertThat(result.resolveAuditConfidence()).isEqualTo(0.91);
    }
}


