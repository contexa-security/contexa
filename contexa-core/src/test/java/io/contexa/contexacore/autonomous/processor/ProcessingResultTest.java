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
}


