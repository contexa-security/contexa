package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class PostprocessingStepTest {

    @Test
    void executeCopiesPromptRuntimeTelemetryIntoAiResponseMetadata() {
        PostprocessingStep step = new PostprocessingStep(Optional.empty());
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        SecurityDecisionResponse parsedResponse = new SecurityDecisionResponse();
        parsedResponse.setAction("ALLOW");
        context.addStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, parsedResponse);
        context.addMetadata("targetResponseType", SecurityDecisionResponse.class);
        context.addMetadata("promptVersion", "2026.03.27-e0.2");
        context.addMetadata("promptHash", "sha256:test-prompt");
        context.addMetadata("budgetProfile", "CORTEX_L1_STANDARD");
        context.addMetadata("promptEvidenceCompleteness", "SUFFICIENT");
        context.addMetadata("promptSectionSet", List.of("CURRENT_REQUEST", "SESSION_NARRATIVE"));
        context.addMetadata("omittedSections", List.of("RAG_CONTEXT"));
        context.addMetadata("promptOmissionCount", 1);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) result;
        assertThat(response.getMetadata("promptVersion", String.class)).isEqualTo("2026.03.27-e0.2");
        assertThat(response.getMetadata("promptHash", String.class)).isEqualTo("sha256:test-prompt");
        assertThat(response.getMetadata("budgetProfile", String.class)).isEqualTo("CORTEX_L1_STANDARD");
        assertThat(response.getMetadata("promptEvidenceCompleteness", String.class)).isEqualTo("SUFFICIENT");
        assertThat(response.getMetadata("promptOmissionCount", Integer.class)).isEqualTo(1);
        assertThat(response.getMetadata("promptSectionSet", List.class)).contains("CURRENT_REQUEST", "SESSION_NARRATIVE");
        assertThat(response.getMetadata("omittedSections", List.class)).contains("RAG_CONTEXT");
    }
}
