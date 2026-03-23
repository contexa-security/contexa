package io.contexa.contexacore.autonomous.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityResponseTest {

    @Test
    void fromJsonParsesCurrentContractWithoutEvidenceField() {
        String json = """
                {
                  "action": "BLOCK",
                  "reasoning": "Impossible travel and new device were observed.",
                  "riskScore": 0.91,
                  "confidence": 0.84,
                  "mitre": "TA0001"
                }
                """;

        SecurityResponse response = SecurityResponse.fromJson(json);

        assertThat(response).isNotNull();
        assertThat(response.getAction()).isEqualTo("BLOCK");
        assertThat(response.getReasoning()).contains("Impossible travel");
        assertThat(response.getRiskScore()).isEqualTo(0.91);
        assertThat(response.getConfidence()).isEqualTo(0.84);
        assertThat(response.getMitre()).isEqualTo("TA0001");
    }
}
