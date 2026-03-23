package io.contexa.contexacore.autonomous.domain;

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
}
