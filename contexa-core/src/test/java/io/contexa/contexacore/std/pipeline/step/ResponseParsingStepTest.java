package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
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
}