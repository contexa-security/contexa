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
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacore.std.pipeline.step.ScriptedChatModel;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V-5 of docs/showcase/프롬프트-v21-구현계획.md (발견 6): a v21 retry whose answer still cites what the prompt does not
 * give is kept as the model gave it, and the record of that retry names the same failure in the model call's retry
 * fields as in the run's retries, so the seal's integrity check reads them as one retry.
 */
class V21RetryRecordTest {

    private static final String WRONG_CITATION = "{\"action\":\"ESCALATE\",\"hypotheses\":[{\"id\":\"H1\",\"name\":null,"
            + "\"assessment\":\"POSSIBLE\",\"for\":[\"S1\"],\"against\":[\"F1\"]},{\"id\":\"H3\",\"name\":null,"
            + "\"assessment\":\"MOST_LIKELY\",\"for\":[\"F1\"],\"against\":[]}],\"reasonCodes\":[{\"code\":"
            + "\"DEVIATION_TIME\",\"fact\":\"F99\"}],\"reason\":\"The owner exports a project outside their work at"
            + " night.\",\"riskScore\":0.7,\"confidence\":0.6,\"mitre\":null}";

    @Test
    void aRetryWhoseCitationStaysWrongNamesItsFailureInTheCallFieldsAndInTheRetries() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        JsonNode a3 = golden.cases().stream().filter(item -> "A3".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(a3,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        AnsweringClient client = new AnsweringClient(WRONG_CITATION);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-v21-retry-record");
        context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, new PromptGenerationResult(
                new Prompt(rendered.userText()), rendered.systemText(), rendered.userText(), Map.of(),
                rendered.executionMetadata()));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        SecurityEvent event = SecurityEvent.builder().eventId("event-v21-retry-record").metadata(new LinkedHashMap<>())
                .build();
        event.addMetadata("sealedEvidence.canonicalContext", rendered.canonicalContext());
        SecurityDecisionRequest request = new SecurityDecisionRequest(new SecurityDecisionContext(event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of()));

        Object response = new LLMExecutionStep(client).execute(request, context).block();

        assertThat(response).as("the answer is kept as the model gave it").isEqualTo(WRONG_CITATION);
        assertThat(client.calls).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isFalse();
        String failure = context.getMetadata("securityDecisionOutputRetryFailureReason", String.class);
        assertThat(failure).contains("REASON_CODE_MISMATCH").contains("F99");
        assertThat(context.getMetadata(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS, String.class))
                .isEqualTo(failure);
        assertThat(context.getMetadata(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.class)).singleElement()
                .satisfies(retry -> assertThat(((Map<?, ?>) retry).get("failureReason")).isEqualTo(failure));
    }

    /** An answer whose only fault is a code citing a line that exists but that the code may not cite (RL-4). */
    private static final String UNSUPPORTED_CODE = "{\"action\":\"BLOCK\",\"hypotheses\":[{\"id\":\"H1\",\"name\":null,"
            + "\"assessment\":\"POSSIBLE\",\"for\":[\"S1\"],\"against\":[\"F1\"]},{\"id\":\"H3\",\"name\":null,"
            + "\"assessment\":\"MOST_LIKELY\",\"for\":[\"F1\"],\"against\":[]}],\"reasonCodes\":[{\"code\":"
            + "\"DEVIATION_NETWORK\",\"fact\":\"F1\"}],\"reason\":\"The owner exports a project outside their work at"
            + " night.\",\"riskScore\":0.9,\"confidence\":0.8,\"mitre\":null}";

    /**
     * RL-4: reason codes the lines do not support are the only fault, so the step does not ask again (a second answer
     * may choose another action: in the A6 measurement three BLOCK answers became ALLOW that way). The first answer is
     * kept and the codes are recorded as unresolved findings; with a made-up fact ID, as above, it still asks again.
     */
    @Test
    void anAnswerWhoseOnlyFaultIsUnsupportedCodesIsKeptWithoutAskingAgain() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        JsonNode a3 = golden.cases().stream().filter(item -> "A3".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(a3,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        AnsweringClient client = new AnsweringClient(UNSUPPORTED_CODE);
        PipelineExecutionContext context = contextOf(rendered, "exec-v21-unsupported-codes");

        Object response = new LLMExecutionStep(client).execute(requestOf(rendered), context).block();

        assertThat(response).as("the first answer, as the model gave it").isEqualTo(UNSUPPORTED_CODE);
        assertThat(client.calls).as("no second model call").isEqualTo(1);
        assertThat(context.getMetadata("securityDecisionOutputRetryAttempted", Boolean.class)).isNotEqualTo(Boolean.TRUE);
        assertThat(context.getMetadata(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS, String.class))
                .contains("REASON_CODE_MISMATCH").contains("DEVIATION_NETWORK F1");
        assertThat(context.getMetadata(SecurityDecisionV21OutputInspector.HYPOTHESES, List.class)).hasSize(2);
    }

    /** An ESCALATE that cites only what the A3 prompt states. */
    private static final String CITED_ESCALATE = "{\"action\":\"ESCALATE\",\"hypotheses\":[{\"id\":\"H1\",\"name\":null,"
            + "\"assessment\":\"UNLIKELY\",\"for\":[\"S1\"],\"against\":[\"F1\",\"F4\"]},{\"id\":\"H2\",\"name\":null,"
            + "\"assessment\":\"POSSIBLE\",\"for\":[\"F1\"],\"against\":[\"F2\"]},{\"id\":\"H3\",\"name\":null,"
            + "\"assessment\":\"MOST_LIKELY\",\"for\":[\"F1\",\"F4\",\"R4\"],\"against\":[]},{\"id\":\"H4\",\"name\":null,"
            + "\"assessment\":\"NO_EVIDENCE\",\"for\":[],\"against\":[]}],\"reasonCodes\":[{\"code\":\"DEVIATION_TIME\","
            + "\"fact\":\"F1\"},{\"code\":\"NO_COVERING_RECORD\",\"fact\":\"F3\"},{\"code\":\"DATA_NATURE_MISMATCH\","
            + "\"fact\":\"R4\"}],\"reason\":\"The owner exports a project outside their work at night.\","
            + "\"riskScore\":0.7,\"confidence\":0.6,\"mitre\":null}";

    /**
     * 판정층 E-3 (docs/showcase/판정층-수정계획.md): the pipeline step asks a second pass that answers ESCALATE once more
     * for one of ALLOW, CHALLENGE or BLOCK, by the mark the second pass render leaves; a first pass ESCALATE, which
     * hands the request to the second pass, is kept at once.
     */
    @Test
    void aSecondPassEscalateIsAskedOnceMoreAndAFirstPassEscalateIsKept() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        JsonNode a3 = golden.cases().stream().filter(item -> "A3".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        SecurityDecisionGoldenRender.RenderedCase first = golden.render(a3,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        SecurityDecisionGoldenRender.RenderedCase second = golden.render(a3,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties, null,
                V21SecondPassAnswerTest.secondPassOf(first));

        AnsweringClient firstClient = new AnsweringClient(CITED_ESCALATE);
        PipelineExecutionContext firstContext = contextOf(first, "exec-v21-first-escalate");
        Object firstResponse = new LLMExecutionStep(firstClient).execute(requestOf(first), firstContext).block();
        AnsweringClient secondClient = new AnsweringClient(CITED_ESCALATE);
        PipelineExecutionContext secondContext = contextOf(second, "exec-v21-second-escalate");
        new LLMExecutionStep(secondClient).execute(requestOf(second), secondContext).block();

        assertThat(firstResponse).isEqualTo(CITED_ESCALATE);
        assertThat(firstClient.calls).isEqualTo(1);
        assertThat(secondClient.calls).isEqualTo(2);
        assertThat(secondContext.getMetadata("securityDecisionOutputRetryFailureReason", String.class))
                .contains("SECOND_PASS_ESCALATE");
    }

    /**
     * QF-50 (DD-65 A): a v21 corrective retry goes out with the first call's output limit and a longer prompt, so the
     * model can spend the whole limit thinking and the provider ends at the limit before any text. That retry is asked
     * again once with twice the limit, and the decision is read from that answer as the retry's (one retry, as the
     * seal's integrity check reads it). Through the orchestrator, so the thinking-only answer fails as in production.
     */
    @Test
    void aCorrectiveRetryCutBeforeAnyTextIsAskedAgainWithTwiceTheOutputLimit() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        JsonNode a3 = golden.cases().stream().filter(item -> "A3".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(a3,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        ScriptedChatModel model = new ScriptedChatModel(ScriptedChatModel.answer(WRONG_CITATION, "end_turn"),
                ScriptedChatModel.thinkingOnly("max_tokens"), ScriptedChatModel.answer(CITED_ESCALATE, "end_turn"));
        PipelineExecutionContext context = contextOf(rendered, "exec-v21-qf50");
        SecurityDecisionRequest request = requestOf(rendered);
        request.withParameter("platformSecurityDecisionMaxTokens", 2048);

        Object response = new LLMExecutionStep(model.orchestrator()).execute(request, context).block();

        assertThat(model.maxTokens()).as("output limits of the model calls; failure category %s",
                context.getMetadata("structuredOutputFailureCategory", String.class)).containsExactly(2048, 2048, 4096);
        List<Integer> messages = model.messageCounts();
        assertThat(messages.get(1)).as("the corrective prompt").isEqualTo(messages.get(0) + 2);
        assertThat(messages.get(2)).as("the corrective prompt again").isEqualTo(messages.get(1));
        assertThat(response).isEqualTo(CITED_ESCALATE);
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isTrue();
        String reason = context.getMetadata("securityDecisionOutputRetryReason", String.class);
        assertThat(reason).contains("REASON_CODE_MISMATCH").contains("F99");
        assertThat(context.getMetadata(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.class))
                .isEqualTo(List.of(Map.of("reason", reason, "succeeded", true)));
        assertThat(context.getMetadata(SecurityDecisionV21OutputInspector.HYPOTHESES, List.class)).hasSize(4);
    }

    private static PipelineExecutionContext contextOf(SecurityDecisionGoldenRender.RenderedCase rendered, String id) {
        PipelineExecutionContext context = new PipelineExecutionContext(id);
        context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, new PromptGenerationResult(
                new Prompt(rendered.userText()), rendered.systemText(), rendered.userText(), Map.of(),
                rendered.executionMetadata()));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        return context;
    }

    private static SecurityDecisionRequest requestOf(SecurityDecisionGoldenRender.RenderedCase rendered) {
        SecurityEvent event = SecurityEvent.builder().eventId("event-v21-escalate").metadata(new LinkedHashMap<>())
                .build();
        event.addMetadata("sealedEvidence.canonicalContext", rendered.canonicalContext());
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
            return Mono.error(new UnsupportedOperationException("a v21 decision is read raw"));
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            calls++;
            return Mono.just(answer);
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            return Mono.error(new UnsupportedOperationException("a v21 decision is read raw"));
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return Flux.just(answer);
        }
    }
}
