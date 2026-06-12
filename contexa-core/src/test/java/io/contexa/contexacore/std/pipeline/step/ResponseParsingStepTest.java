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
package io.contexa.contexacore.std.pipeline.step;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

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
        assertThat(result).isInstanceOf(HashMap.class);
        assertThat(context.getMetadata("parsingComplete", Boolean.class)).isTrue();
        assertThat(context.getMetadata("responseType", String.class)).isEqualTo("HashMap");
    }

    @Test
    void executeShouldParseRawSecurityDecisionTextWithGuardedParser() {
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

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite parsed = (SecurityDecisionResponseLite) result;
        assertThat(parsed.getAction()).isEqualTo("CHALLENGE");
        assertThat(parsed.getConfidence()).isEqualTo(0.65d);
        assertThat(parsed.getReasoning()).isEqualTo("Sparse baseline and high-value access require additional verification.");
        assertThat(context.getMetadata("securityDecisionParsingMode", String.class)).isEqualTo("RAW_GUARDED");
        assertThat(context.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class)).isFalse();
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isTrue();
    }

    @Test
    void executeShouldFailClosedForEmptySecurityDecisionResponse() {
        ResponseParsingStep step = new ResponseParsingStep();
        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(null, null, null, List.of()));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, "");
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(SecurityDecisionResponseLite.class);
        SecurityDecisionResponseLite parsed = (SecurityDecisionResponseLite) result;
        assertThat(parsed.getAction()).isEqualTo("CHALLENGE");
        assertThat(parsed.getReasoning()).isEqualTo("Model output was incomplete; challenge is required.");
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("EMPTY_RESPONSE");
        assertThat(context.getMetadata("syntheticSecurityDecisionApplied", Boolean.class)).isTrue();
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
