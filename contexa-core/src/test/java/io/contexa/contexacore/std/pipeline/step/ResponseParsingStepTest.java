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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    void executeShouldRejectRawSecurityDecisionTextWhenStructuredOutputIsMissing() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.LLM_EXECUTION,
                "Action: CHALLENGE\nConfidence: 0.65\nReasoning: Sparse baseline and high-value access require additional verification.\nMITRE: UNKNOWN");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        context.addMetadata("rawExecutionAttempted", true);

        assertThatThrownBy(() -> step.execute(request, context).block())
                .isInstanceOfSatisfying(StructuredOutputExecutionException.class, exception -> {
                    assertThat(exception.getCategory()).isEqualTo(StructuredOutputFailureCategory.RAW_EXECUTION_FORBIDDEN);
                    assertThat(exception.getFailure()).isNotNull();
                    assertThat(exception.getFailure().category()).isEqualTo(DecisionFailureCategory.RAW_EXECUTION_FORBIDDEN);
                })
                .hasMessageContaining("Raw parsing is forbidden");
    }

    @Test
    void executeShouldRejectEmptySecurityDecisionResponse() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, "");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        assertThatThrownBy(() -> step.execute(request, context).block())
                .isInstanceOfSatisfying(StructuredOutputExecutionException.class, exception -> {
                    assertThat(exception.getCategory()).isEqualTo(StructuredOutputFailureCategory.EMPTY_RESPONSE);
                    assertThat(exception.getFailure()).isNotNull();
                    assertThat(exception.getFailure().category()).isEqualTo(DecisionFailureCategory.EMPTY_RESPONSE);
                })
                .hasMessageContaining("Structured response is missing");
    }

    @Test
    void executeShouldPassThroughStructuredSecurityDecisionResponse() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ALLOW");
        lite.setConfidence(0.74d);
        lite.setRiskScore(0.22d);
        lite.setReasoning("Verified identity, scope, and low-risk context align with the request.");
        lite.setMitre("UNKNOWN");
        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, lite);
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        context.addMetadata("structuredOutputComplete", true);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite parsed = (SecurityDecisionResponseLite) result;
        assertThat(parsed.getAction()).isEqualTo("ALLOW");
        assertThat(parsed.getConfidence()).isEqualTo(0.74d);
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class)).isFalse();
        assertThat(context.getMetadata("syntheticSecurityDecisionApplied", Boolean.class)).isFalse();
    }
}
