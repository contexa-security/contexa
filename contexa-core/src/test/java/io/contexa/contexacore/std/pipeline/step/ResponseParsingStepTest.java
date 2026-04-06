package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ResponseParsingStepTest {

    @Test
    void executeShouldTreatMissingStructuredOutputFlagAsFalse() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, "{\"action\":\"ALLOW\"}");
        context.addMetadata("targetResponseType", Map.class);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(Map.class);
        assertThat(result).isInstanceOf(java.util.HashMap.class);
        assertThat(context.getMetadata("parsingComplete", Boolean.class)).isTrue();
        assertThat(context.getMetadata("responseType", String.class)).isEqualTo("HashMap");
    }

    @Test
    void executeShouldCoerceRawSecurityDecisionTextIntoLiteResponse() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.LLM_EXECUTION,
                "Action: CHALLENGE\nConfidence: 0.65\nReasoning: Sparse baseline and high-value access require additional verification.\nMITRE: UNKNOWN");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite lite = (SecurityDecisionResponseLite) result;
        assertThat(lite.getAction()).isEqualTo("CHALLENGE");
        assertThat(lite.getConfidence()).isEqualTo(0.65d);
        assertThat(lite.getReasoning()).contains("additional verification");
        assertThat(lite.getMitre()).isEqualTo("UNKNOWN");
    }

    @Test
    void executeShouldReturnSafeFallbackForEmptySecurityDecisionResponse() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, "");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite lite = (SecurityDecisionResponseLite) result;
        assertThat(lite.getAction()).isEqualTo("BLOCK");
        assertThat(lite.getReasoning()).contains("No response from LLM");
    }

    @Test
    void executeShouldNormalizeMarkdownFinalDecisionIntoCanonicalAction() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.LLM_EXECUTION,
                "**Final Decision:** DENY\nConfidence: HIGH\nReasoning: Approval lineage is absent for this sensitive request.\nMITRE: UNKNOWN");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite lite = (SecurityDecisionResponseLite) result;
        assertThat(lite.getAction()).isEqualTo("BLOCK");
        assertThat(lite.getConfidence()).isEqualTo(0.85d);
        assertThat(lite.getReasoning()).contains("Approval lineage is absent");
    }

    @Test
    void executeShouldCoerceLabeledConfidenceFromJsonDecisionPayload() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.LLM_EXECUTION,
                "{\"action\":\"ALLOW\",\"confidence\":\"MODERATE\",\"riskScore\":\"LOW\",\"reasoning\":\"Baseline aligns with the restored session.\",\"mitre\":\"UNKNOWN\"}");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite lite = (SecurityDecisionResponseLite) result;
        assertThat(lite.getAction()).isEqualTo("ALLOW");
        assertThat(lite.getConfidence()).isEqualTo(0.74d);
        assertThat(lite.getRiskScore()).isEqualTo(0.54d);
    }
}
