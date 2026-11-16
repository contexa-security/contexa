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

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionCompactAnswer;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v1.0 (plan 2.4 D1): an answer that still breaks a boundary after the one retry is replaced by the boundary's action in
 * a fallback variant, as v19 and v20 replaced it, and kept with the breach recorded for review in a record variant.
 */
class V1RetryFallbackTest {

    /** A BLOCK the A1 facts do not support: no boundary of the decision rules requires it. */
    private static final String UNSUPPORTED_BLOCK = "{\"action\":\"BLOCK\",\"hypotheses\":[],\"reasonCodes\":[],"
            + "\"reason\":\"The request looks harmful.\",\"riskScore\":0.9,\"confidence\":0.8,\"mitre\":null}";

    @Test
    void aFallbackVariantReplacesAnAnswerThatStillBreaksABoundary() {
        SecurityDecisionGoldenRender.RenderedCase rendered = render(SecurityDecisionPromptBundles.V1_FALLBACK_EXACT);
        AnsweringClient client = new AnsweringClient(UNSUPPORTED_BLOCK);
        PipelineExecutionContext context = contextOf(rendered, "exec-v1-fallback");

        // As the v20 response check: the failure goes on to the parser, which takes the fallback action named here.
        new LLMExecutionStep(client)
                .execute(requestOf(rendered, SecurityDecisionPromptBundles.V1_FALLBACK_EXACT), context).block();

        assertThat(client.calls).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryFailureReason", String.class))
                .contains(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(context.getMetadata(SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION, String.class))
                .isEqualTo(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                        SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE));
        assertThat(context.getMetadata(SecurityDecisionV1OutputInspector.V1_RULE_BREACH, String.class)).isNull();
    }

    /**
     * Plan 6-2 (D6): v1.0 whose version includes the decision rules replaces the answer as the fallback variant did; the
     * strategy names it on the request, as it names the short answer.
     */
    @Test
    void aVersionWithTheDecisionRulesReplacesAnAnswerThatStillBreaksABoundaryAsTheFallbackVariantDid() {
        SecurityDecisionGoldenRender.RenderedCase rendered = render(SecurityDecisionPromptBundles.V1);
        AnsweringClient client = new AnsweringClient(UNSUPPORTED_BLOCK);
        PipelineExecutionContext context = contextOf(rendered, "exec-v1-version-fallback");
        SecurityDecisionRequest request = requestOf(rendered, SecurityDecisionPromptBundles.V1);
        request.withParameter(SecurityDecisionCompactAnswer.REQUEST_PARAMETER, true);
        request.withParameter(SecurityDecisionV1OutputInspector.FALLBACK_PARAMETER, true);

        new LLMExecutionStep(client).execute(request, context).block();

        assertThat(client.calls).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryFailureReason", String.class))
                .contains(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(context.getMetadata(SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION, String.class))
                .isEqualTo(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                        SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE));
        assertThat(context.getMetadata(SecurityDecisionV1OutputInspector.V1_RULE_BREACH, String.class)).isNull();
    }

    /** Plan 6-2: the product version, without the decision rules, keeps the answer and records the breach. */
    @Test
    void theProductVersionKeepsTheAnswerAndRecordsTheBreachAsTheRecordVariantDid() {
        SecurityDecisionGoldenRender.RenderedCase rendered = render(SecurityDecisionPromptBundles.V1);
        AnsweringClient client = new AnsweringClient(UNSUPPORTED_BLOCK);
        PipelineExecutionContext context = contextOf(rendered, "exec-v1-version-record");
        SecurityDecisionRequest request = requestOf(rendered, SecurityDecisionPromptBundles.V1);
        request.withParameter(SecurityDecisionCompactAnswer.REQUEST_PARAMETER, true);

        Object response = new LLMExecutionStep(client).execute(request, context).block();

        assertThat(response).as("the model's answer stays").isEqualTo(UNSUPPORTED_BLOCK);
        assertThat(client.calls).isEqualTo(2);
        assertThat(context.getMetadata(SecurityDecisionV1OutputInspector.V1_RULE_BREACH, String.class))
                .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(context.getMetadata(SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION, String.class))
                .isNull();
    }

    @Test
    void aRecordVariantKeepsTheAnswerAndRecordsTheBreachForReview() {
        SecurityDecisionGoldenRender.RenderedCase rendered = render(SecurityDecisionPromptBundles.V1_RECORD_EXACT);
        AnsweringClient client = new AnsweringClient(UNSUPPORTED_BLOCK);
        PipelineExecutionContext context = contextOf(rendered, "exec-v1-record");

        Object response = new LLMExecutionStep(client)
                .execute(requestOf(rendered, SecurityDecisionPromptBundles.V1_RECORD_EXACT), context).block();

        assertThat(response).as("the model's answer stays").isEqualTo(UNSUPPORTED_BLOCK);
        assertThat(client.calls).isEqualTo(2);
        // Plan 2.3 A18, A19: the answer is read by the output contract v4, whose reason limit the processor applies.
        assertThat(context.getMetadata(SecurityDecisionV21OutputInspector.OUTPUT_CONTRACT, String.class))
                .isEqualTo(SecurityDecisionV21OutputInspector.OUTPUT_CONTRACT_V4);
        assertThat(context.getMetadata(SecurityDecisionV1OutputInspector.V1_RULE_BREACH, String.class))
                .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(context.getMetadata(SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION, String.class))
                .isNull();
    }

    /**
     * Plan 2.3 A8, A9 and 2.2 ⑤: a v1.0 second analysis draws the SECOND PASS block over the first prompt, as v21 does,
     * and its ESCALATE, which hands the request to no one, is asked again for a response.
     */
    @Test
    void aV1SecondAnalysisDrawsItsBlockAndAnEscalateIsAskedAgain() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V1_RECORD_EXACT.version());
        JsonNode a1 = golden.cases().stream().filter(item -> "A1".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        String first = golden.render(a1, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties).userText();
        SecurityDecisionGoldenRender.RenderedCase second = golden.render(a1, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT,
                properties, null, Map.of("layer2FirstPassUserPrompt", first, "layer2FirstPassVerdict", "ESCALATE",
                        "layer2FirstPassPastRecordsState", "TIMEOUT"));
        AnsweringClient client = new AnsweringClient("{\"action\":\"ESCALATE\",\"hypotheses\":[],\"reasonCodes\":[],"
                + "\"reason\":\"The facts conflict.\",\"riskScore\":null,\"confidence\":null,\"mitre\":null}");
        PipelineExecutionContext context = contextOf(second, "exec-v1-second-pass");

        new LLMExecutionStep(client).execute(requestOf(second, SecurityDecisionPromptBundles.V1_RECORD_EXACT), context)
                .block();

        assertThat(second.userText()).startsWith(first.stripTrailing()).contains("=== SECOND PASS");
        assertThat(client.calls).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryReason", String.class))
                .contains(SecurityDecisionV21OutputInspector.SECOND_PASS_ESCALATE);
    }

    private static SecurityDecisionGoldenRender.RenderedCase render(SecurityDecisionPromptBundles.Bundle bundle) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        JsonNode a1 = golden.cases().stream().filter(item -> "A1".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        return golden.render(a1, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
    }

    private static PipelineExecutionContext contextOf(SecurityDecisionGoldenRender.RenderedCase rendered, String id) {
        PipelineExecutionContext context = new PipelineExecutionContext(id);
        context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, new PromptGenerationResult(
                new Prompt(rendered.userText()), rendered.systemText(), rendered.userText(), Map.of(),
                rendered.executionMetadata()));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        return context;
    }

    private static SecurityDecisionRequest requestOf(SecurityDecisionGoldenRender.RenderedCase rendered,
                                                     SecurityDecisionPromptBundles.Bundle bundle) {
        SecurityEvent event = SecurityEvent.builder().eventId("event-v1-retry").metadata(new LinkedHashMap<>())
                .build();
        event.addMetadata("sealedEvidence.canonicalContext", rendered.canonicalContext());
        event.addMetadata(SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION, bundle.version());
        return new SecurityDecisionRequest(new SecurityDecisionContext(event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of()));
    }

    /** The model, answering every call with the same text. */
    private static final class AnsweringClient implements LLMClient, LLMOperations {

        private final String answer;
        private int calls;

        private AnsweringClient(String answer) {
            this.answer = answer;
        }

        @Override
        public Mono<String> execute(ExecutionContext context) {
            calls++;
            return Mono.just(answer);
        }

        @Override
        public Flux<String> stream(ExecutionContext context) {
            return Flux.just(answer);
        }

        @Override
        public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {
            return Mono.error(new UnsupportedOperationException("a v1.0 decision is read raw"));
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            calls++;
            return Mono.just(answer);
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            return Mono.error(new UnsupportedOperationException("a v1.0 decision is read raw"));
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return Flux.just(answer);
        }
    }
}
