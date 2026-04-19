package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    @Test
    void wrapResponseShouldRejectMultiSentenceReasoning() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("CHALLENGE");
        lite.setReasoning("Role scope is provisional. Approval lineage is missing.");
        lite.setRiskScore(0.4);
        lite.setConfidence(0.6);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        assertThatThrownBy(() -> processor.wrapResponse(lite, new PipelineExecutionContext("req-2")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exactly one sentence");
    }

    @Test
    void wrapResponseShouldRejectReasoningLongerThanFortyWords() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ESCALATE");
        lite.setReasoning("Role scope remains provisional because approval lineage resource scope session continuity device familiarity location consistency historical baseline coverage comparable evidence quality sensitive resource intent workflow context and governance posture all require explicit reconciliation before autonomous access can be considered safe for this production decision.");
        lite.setRiskScore(0.5);
        lite.setConfidence(0.58);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        assertThatThrownBy(() -> processor.wrapResponse(lite, new PipelineExecutionContext("req-3")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds 40 words");
    }

    @Test
    void wrapResponseShouldRejectAllowWithExtremeRiskScore() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ALLOW");
        lite.setReasoning("Observed evidence is limited and remains provisional.");
        lite.setRiskScore(1.0);
        lite.setConfidence(0.62);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        assertThatThrownBy(() -> processor.wrapResponse(lite, new PipelineExecutionContext("req-4")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ALLOW")
                .hasMessageContaining("extreme risk score");
    }
}
