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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import java.util.List;
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
    void wrapResponseShouldNormalizeMultiSentenceReasoningWithoutStoppingDecision() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("CHALLENGE");
        lite.setReasoning("Role scope is provisional. Approval lineage is missing.");
        lite.setRiskScore(0.4);
        lite.setConfidence(0.6);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();
        PipelineExecutionContext context = new PipelineExecutionContext("req-2");

        Object wrapped = processor.wrapResponse(lite, context);

        assertThat(wrapped).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) wrapped;
        assertThat(response.getReasoning()).isEqualTo("Role scope is provisional");
        assertThat(context.getMetadata("securityDecisionPostprocessingRepairApplied", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionPostprocessingRepairFields", List.class)).contains("reasoning");
    }

    @Test
    void wrapResponseShouldTrimLongReasoningWithoutStoppingDecision() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ESCALATE");
        lite.setReasoning("Role scope remains provisional because approval lineage resource scope session continuity device familiarity location consistency historical baseline coverage comparable evidence quality sensitive resource intent workflow context and governance posture all require explicit reconciliation before autonomous access can be considered safe for this production decision.");
        lite.setRiskScore(0.5);
        lite.setConfidence(0.58);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();
        PipelineExecutionContext context = new PipelineExecutionContext("req-3");

        Object wrapped = processor.wrapResponse(lite, context);

        assertThat(wrapped).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) wrapped;
        assertThat(response.getReasoning().split("\\s+")).hasSizeLessThanOrEqualTo(40);
        assertThat(context.getMetadata("securityDecisionPostprocessingRepairFields", List.class)).contains("reasoning");
    }

    @Test
    void wrapResponseShouldRecordSemanticWarningForAllowWithExtremeRiskScoreWithoutStoppingDecision() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ALLOW");
        lite.setReasoning("Observed evidence is limited and remains provisional.");
        lite.setRiskScore(1.0);
        lite.setConfidence(0.62);
        lite.setMitre("UNKNOWN");

        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();
        PipelineExecutionContext context = new PipelineExecutionContext("req-4");

        Object wrapped = processor.wrapResponse(lite, context);

        assertThat(wrapped).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) wrapped;
        assertThat(response.getAction()).isEqualTo("ALLOW");
        assertThat(response.getRiskScore()).isEqualTo(1.0);
        assertThat(context.getMetadata("securityDecisionSemanticWarning", String.class))
                .isEqualTo("ALLOW_WITH_EXTREME_RISK_SCORE");
    }

    @Test
    void wrapResponseShouldDefaultMissingMetadataWithoutStoppingDecision() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("BLOCK");

        PipelineExecutionContext context = new PipelineExecutionContext("req-5");
        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        Object wrapped = processor.wrapResponse(lite, context);

        assertThat(wrapped).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) wrapped;
        assertThat(response.getAction()).isEqualTo("BLOCK");
        assertThat(response.getRiskScore()).isEqualTo(0.90);
        assertThat(response.getConfidence()).isEqualTo(0.70);
        assertThat(response.getMitre()).isEqualTo("UNKNOWN");
        assertThat(response.getReasoning()).isEqualTo("Decision metadata was incomplete; block remains required.");
        assertThat(context.getMetadata("securityDecisionPostprocessingRepairFields", List.class))
                .contains("riskScore", "confidence", "reasoning", "mitre");
    }

    @Test
    void wrapResponseShouldFailClosedWhenActionIsMissing() {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setReasoning("The model omitted the required action field.");

        PipelineExecutionContext context = new PipelineExecutionContext("req-missing-action");
        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        Object wrapped = processor.wrapResponse(lite, context);

        assertThat(wrapped).isInstanceOf(SecurityDecisionResponse.class);
        SecurityDecisionResponse response = (SecurityDecisionResponse) wrapped;
        assertThat(response.getAction()).isEqualTo("CHALLENGE");
        assertThat(response.getRiskScore()).isEqualTo(0.55);
        assertThat(response.getConfidence()).isEqualTo(0.60);
        assertThat(context.getMetadata("securityDecisionFallbackApplied", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionFallbackAction", String.class)).isEqualTo("CHALLENGE");
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isFalse();
    }

    @Test
    void wrapResponseShouldRejectMapBecauseRawParsingBelongsToSecurityDecisionOutputParser() {
        SecurityDecisionResponseProcessor processor = new SecurityDecisionResponseProcessor();

        assertThatThrownBy(() -> processor.wrapResponse(
                java.util.Map.of("action", "CHALLENGE"),
                new PipelineExecutionContext("req-6")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Expected SecurityDecisionResponseLite");
    }
}
