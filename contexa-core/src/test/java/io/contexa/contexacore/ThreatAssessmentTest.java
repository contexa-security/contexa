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
package io.contexa.contexacore;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ThreatAssessmentTest {

    @Test
    void getConfidenceScoreReturnsAuditConfidenceWhenLegacyConfidenceIsNull() {
        ThreatAssessment assessment = ThreatAssessment.builder()
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(0.64)
                .llmAuditConfidence(0.92)
                .build();

        assertThat(assessment.getRiskScore()).isNull();
        assertThat(assessment.getConfidence()).isNull();
        assertThat(assessment.resolveAuditRiskScore()).isEqualTo(0.64);
        assertThat(assessment.getConfidenceScore()).isEqualTo(0.92);
    }

    @Test
    void confidenceScorePrefersEffectiveConfidenceWhenPresent() {
        ThreatAssessment assessment = ThreatAssessment.builder()
                .confidence(0.58)
                .llmAuditConfidence(0.93)
                .action("ALLOW")
                .autonomousAction("CHALLENGE")
                .build();

        assertThat(assessment.getConfidenceScore()).isEqualTo(0.58);
        assertThat(assessment.getAction()).isEqualTo("ALLOW");
        assertThat(assessment.getAutonomousAction()).isEqualTo("CHALLENGE");
    }
}
