package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionResponseProcessorTest {

    @Test
    void wrapResponseShouldConvertLiteResponseIntoFullSecurityDecisionResponse() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("CHALLENGE");
        lite.setReasoning("critical context is missing");
        lite.setRiskScore(0.7);
        lite.setConfidence(0.6);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        Object wrapped = processor.wrapResponse(lite, new PipelineExecutionContext("req-1"));

        assertThat(wrapped).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) wrapped;
        assertThat(response.getAction()).isEqualTo("CHALLENGE");
        assertThat(response.getReasoning()).isEqualTo("critical context is missing");
        assertThat(response.getRiskScore()).isEqualTo(0.7);
        assertThat(response.getConfidence()).isEqualTo(0.6);
        assertThat(response.getMitre()).isEqualTo("UNKNOWN");
    }
}
