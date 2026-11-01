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
package io.contexa.contexacore.std.llm.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.retry.RetryUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The request body an Anthropic model call sends for a layer's thinking settings, read as Spring AI 1.1.8's own
 * Anthropic model writes it (the real AnthropicChatModel and AnthropicApi over a mock HTTP server; no provider is
 * called). The layer settings travel on the call's metadata as the pipeline step puts them there.
 */
class AnthropicThinkingRequestBodyTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MESSAGES_URL = "https://api.anthropic.com/v1/messages";
    private static final String ANSWER = "{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\","
            + "\"model\":\"m\",\"content\":[{\"type\":\"text\",\"text\":\"{\\\"action\\\":\\\"ALLOW\\\"}\"}],"
            + "\"stop_reason\":\"end_turn\",\"stop_sequence\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}";

    /**
     * T1: with the default settings the body is byte for byte what it was before the settings existed (the golden
     * bodies were captured on the core before this change): Claude Haiku 5.5 at Layer 1, Claude Sonnet 5.5 at Layer 2,
     * and Claude Haiku 4.5, which takes the platform's temperature.
     */
    @Test
    void theDefaultSettingsSendTheBodyOfBefore() {
        assertThat(firstBody("claude-haiku-5-5", 4096, defaultSettings())).isEqualTo(
                "{\"model\":\"claude-haiku-5-5\",\"messages\":[{\"content\":[{\"type\":\"text\",\"text\":\"decide\"}],"
                        + "\"role\":\"user\"}],\"system\":\"system rules\",\"max_tokens\":4096,\"stream\":false}");
        assertThat(firstBody("claude-sonnet-5-5", 2560, defaultSettings())).isEqualTo(
                "{\"model\":\"claude-sonnet-5-5\",\"messages\":[{\"content\":[{\"type\":\"text\",\"text\":\"decide\"}],"
                        + "\"role\":\"user\"}],\"system\":\"system rules\",\"max_tokens\":2560,\"stream\":false}");
        assertThat(firstBody("claude-haiku-4-5", 4096, defaultSettings())).isEqualTo(
                "{\"model\":\"claude-haiku-4-5\",\"messages\":[{\"content\":[{\"type\":\"text\",\"text\":\"decide\"}],"
                        + "\"role\":\"user\"}],\"system\":\"system rules\",\"max_tokens\":4096,\"stream\":false,"
                        + "\"temperature\":0.0}");
    }

    /**
     * Design 4.7 examples 1, 2 and 4 through Spring AI 1.1.8: Claude Haiku 5.5 at Layer 1 with the default settings
     * and with thinking off, and Claude Sonnet 5.5 at Layer 2 with thinking off, which Spring AI 1.1 cannot send.
     */
    @Test
    void theDesignExamplesSendTheseBodies() {
        String messages = "\"messages\":[{\"content\":[{\"type\":\"text\",\"text\":\"decide\"}],\"role\":\"user\"}],"
                + "\"system\":\"system rules\",";
        String haikuDefault = firstBody("claude-haiku-5-5", 4096, defaultSettings());
        String haikuOff = firstBody("claude-haiku-5-5", 4096, settings("OFF", null, 0));
        AnthropicServer sonnet = new AnthropicServer("claude-sonnet-5-5");
        sonnet.answer();
        ExecutionContext sonnetCall = decisionCall(2560, settings("OFF", null, 0));
        sonnet.orchestrator().execute(sonnetCall).block();
        String sonnetOff = sonnet.bodies.get(0);
        System.out.println("EXAMPLE haiku-5-5 L1 default: " + haikuDefault);
        System.out.println("EXAMPLE haiku-5-5 L1 OFF: " + haikuOff);
        System.out.println("EXAMPLE sonnet-5-5 L2 OFF: " + sonnetOff);

        assertThat(haikuDefault).isEqualTo("{\"model\":\"claude-haiku-5-5\"," + messages
                + "\"max_tokens\":4096,\"stream\":false}");
        assertThat(haikuOff).isEqualTo("{\"model\":\"claude-haiku-5-5\"," + messages
                + "\"max_tokens\":4096,\"stream\":false,\"thinking\":{\"type\":\"disabled\"}}");
        assertThat(sonnetOff).isEqualTo("{\"model\":\"claude-sonnet-5-5\"," + messages
                + "\"max_tokens\":2560,\"stream\":false}");
        assertThat(sonnetCall.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("NOT_EXPRESSIBLE_SPRING_AI_1_1"));
    }

    /** T1 records: the default settings send no thinking field, and the call records that and the output limit. */
    @Test
    void theDefaultSettingsRecordTheModelDefaultThinking() {
        AnthropicServer server = new AnthropicServer("claude-haiku-5-5");
        server.answer();
        ExecutionContext call = decisionCall(4096, defaultSettings());

        server.orchestrator().execute(call).block();

        assertThat(call.getMetadata())
                .containsEntry("providerThinkingRequested", "PROVIDER_DEFAULT")
                .containsEntry("providerThinking", "ABSENT")
                .containsEntry("providerThinkingSource", "MODEL_DEFAULT")
                .containsEntry("providerMaxTokensSent", 4096)
                .doesNotContainKey("providerThinkingAdjustment");
    }

    /**
     * T2, T4 (call time), T8: what each thinking setting sends to each row of the Claude API's table through Spring AI
     * 1.1.8: the thinking field, the output limit (answer limit 4,096, budget 2,048, allowance 512) and the platform's
     * temperature 0.0; adaptive thinking and between_tools cannot be sent and are recorded as left out.
     */
    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("settingsPerModel")
    void eachSettingSendsWhatTheModelTakes(String model, String mode, String thinking, int maxTokens,
                                           boolean temperature, String adjustment) throws Exception {
        AnthropicServer server = new AnthropicServer(model);
        server.answer();
        ExecutionContext call = decisionCall(4096, settings(mode, 2048, 512));

        server.orchestrator().execute(call).block();

        JsonNode body = JSON.readTree(server.bodies.get(0));
        assertThat(body.has("thinking") ? body.get("thinking").toString() : null).as("thinking").isEqualTo(thinking);
        assertThat(body.get("max_tokens").asInt()).as("max_tokens").isEqualTo(maxTokens);
        assertThat(body.has("temperature")).as("temperature").isEqualTo(temperature);
        assertThat(body.has("output_config")).as("output_config").isFalse();
        assertThat(call.getMetadata()).containsEntry("providerMaxTokensSent", maxTokens);
        if (adjustment != null) {
            assertThat(call.getMetadata().get("providerThinkingAdjustment")).isEqualTo(List.of(adjustment));
        } else {
            assertThat(call.getMetadata()).doesNotContainKey("providerThinkingAdjustment");
        }
        if (!temperature) {
            assertThat(call.getMetadata().get("determinismNotApplied")).asList().contains("temperature");
        }
    }

    static Stream<Arguments> settingsPerModel() {
        String disabled = "{\"type\":\"disabled\"}";
        String budget = "{\"type\":\"enabled\",\"budget_tokens\":2048}";
        String notExpressible = "NOT_EXPRESSIBLE_SPRING_AI_1_1";
        String budgetRefused = "BUDGET_NOT_ACCEPTED_BY_MODEL";
        String alwaysOn = "OFF_NOT_POSSIBLE_ALWAYS_ON";
        return Stream.of(
                Arguments.of("claude-opus-5-5", "OFF", null, 4608, false, alwaysOn),
                Arguments.of("claude-opus-5-5", "ADAPTIVE", null, 4608, false, notExpressible),
                Arguments.of("claude-opus-5-5", "BUDGET", null, 4608, false, budgetRefused),
                Arguments.of("claude-fable-5-1", "OFF", null, 4608, false, alwaysOn),
                Arguments.of("claude-mythos-preview", "OFF", null, 4608, false, alwaysOn),
                Arguments.of("claude-mythos-preview", "BUDGET", budget, 6144, false, null),
                Arguments.of("claude-opus-5", "OFF", disabled, 4096, false, null),
                Arguments.of("claude-opus-5", "BUDGET", null, 4608, false, budgetRefused),
                Arguments.of("claude-sonnet-5-5", "OFF", null, 4608, false, notExpressible),
                Arguments.of("claude-sonnet-5-5", "ADAPTIVE", null, 4608, false, notExpressible),
                Arguments.of("claude-sonnet-5-5", "BUDGET", null, 4608, false, budgetRefused),
                Arguments.of("claude-sonnet-5", "OFF", disabled, 4096, false, null),
                Arguments.of("claude-haiku-5-5", "OFF", disabled, 4096, false, null),
                Arguments.of("claude-haiku-5-5", "ADAPTIVE", null, 4608, false, notExpressible),
                Arguments.of("claude-haiku-5-5", "BUDGET", null, 4608, false, budgetRefused),
                Arguments.of("claude-opus-4-7", "OFF", disabled, 4096, false, null),
                Arguments.of("claude-opus-4-8", "ADAPTIVE", null, 4096, false, notExpressible),
                Arguments.of("claude-opus-4-7", "BUDGET", null, 4096, false, budgetRefused),
                Arguments.of("claude-sonnet-4-6", "OFF", disabled, 4096, true, null),
                Arguments.of("claude-sonnet-4-6", "ADAPTIVE", null, 4096, true, notExpressible),
                Arguments.of("claude-sonnet-4-6", "BUDGET", budget, 6144, false, null),
                Arguments.of("claude-opus-4-5-20251101", "ADAPTIVE", null, 4096, true, "ADAPTIVE_NOT_ACCEPTED_BY_MODEL"),
                Arguments.of("claude-opus-4-5", "BUDGET", budget, 6144, false, null),
                Arguments.of("claude-haiku-4-5", "OFF", disabled, 4096, true, null),
                Arguments.of("claude-haiku-4-5-20251001", "BUDGET", budget, 6144, false, null),
                Arguments.of("claude-sonnet-4-20250514", "OFF", disabled, 4096, true, null),
                Arguments.of("claude-nova-1", "OFF", disabled, 4096, true, null),
                Arguments.of("claude-nova-1", "ADAPTIVE", null, 4096, true, notExpressible),
                Arguments.of("claude-nova-1", "BUDGET", budget, 6144, false, null));
    }

    /**
     * T8: thinking on an older model takes the temperature out of the request and of the model's defaults (Spring AI's
     * 0.8, which a request cannot null in Spring AI 1.1), and the call records the platform's temperature as not applied.
     */
    @Test
    void thinkingOnAnOlderModelSendsNoTemperature() throws Exception {
        AnthropicServer server = new AnthropicServer("claude-sonnet-4-6");
        server.answer();
        server.answer();
        ExecutionContext budgetCall = decisionCall(4096, settings("BUDGET", 2048, 0));
        ExecutionContext defaultCall = decisionCall(4096, defaultSettings());

        server.orchestrator().execute(budgetCall).block();
        server.orchestrator().execute(defaultCall).block();

        JsonNode body = JSON.readTree(server.bodies.get(0));
        assertThat(body.get("thinking").toString()).isEqualTo("{\"type\":\"enabled\",\"budget_tokens\":2048}");
        assertThat(body.has("temperature")).isFalse();
        assertThat(body.get("max_tokens").asInt()).isEqualTo(6144);
        assertThat(budgetCall.getMetadata().get("determinismNotApplied")).isEqualTo(List.of("temperature", "seed"));
        assertThat(budgetCall.getMetadata()).containsEntry("providerThinking", "ENABLED")
                .containsEntry("providerThinkingBudgetTokens", 2048)
                .containsEntry("providerThinkingSource", "LAYER_SETTING");
        assertThat(JSON.readTree(server.bodies.get(1)).get("temperature").asDouble())
                .as("a call without thinking keeps the platform's temperature").isEqualTo(0.0d);
    }

    /**
     * Design 4.3, PROVIDER_DEFAULT row: a thinking budget in the Spring AI default options is sent as the model's
     * defaults have it, the output limit adds that budget to the answer limit, and the older model loses its temperature.
     */
    @Test
    void aSpringAiDefaultThinkingBudgetIsAddedToTheAnswerLimit() throws Exception {
        AnthropicServer server = new AnthropicServer(AnthropicChatOptions.builder().model("claude-sonnet-4-6")
                .maxTokens(500).temperature(0.8d).thinking(AnthropicApi.ThinkingType.ENABLED, 2048).build());
        server.answer();
        ExecutionContext call = decisionCall(4096, defaultSettings());

        server.orchestrator().execute(call).block();

        JsonNode body = JSON.readTree(server.bodies.get(0));
        assertThat(body.get("thinking").toString()).isEqualTo("{\"type\":\"enabled\",\"budget_tokens\":2048}");
        assertThat(body.get("max_tokens").asInt()).isEqualTo(6144);
        assertThat(body.has("temperature")).isFalse();
        assertThat(call.getMetadata()).containsEntry("providerThinkingSource", "SPRING_AI_DEFAULT_OPTIONS")
                .containsEntry("providerThinking", "ENABLED");
    }

    /**
     * D-2 and D-3 for a model first seen at call time: thinking off with an effort the model takes only at high or
     * below leaves both out; an effort level the model lacks is left out; any effort is recorded as not sendable
     * through Spring AI 1.1 and never reaches the body.
     */
    @Test
    void anEffortIsNeverSentAndAConflictLeavesBothFieldsOut() throws Exception {
        AnthropicServer conflict = new AnthropicServer("claude-haiku-5-5");
        conflict.answer();
        Map<String, Object> offWithXhigh = settings("OFF", null, 0);
        offWithXhigh.put("anthropicEffort", "XHIGH");
        AnthropicServer lacking = new AnthropicServer("claude-sonnet-4-6");
        lacking.answer();
        Map<String, Object> xhighOnSonnet46 = settings("PROVIDER_DEFAULT", null, 0);
        xhighOnSonnet46.put("anthropicEffort", "XHIGH");
        AnthropicServer low = new AnthropicServer("claude-haiku-5-5");
        low.answer();
        Map<String, Object> lowEffort = settings("OFF", null, 0);
        lowEffort.put("anthropicEffort", "LOW");

        ExecutionContext conflictCall = decisionCall(4096, offWithXhigh);
        ExecutionContext lackingCall = decisionCall(4096, xhighOnSonnet46);
        ExecutionContext lowCall = decisionCall(4096, lowEffort);
        conflict.orchestrator().execute(conflictCall).block();
        lacking.orchestrator().execute(lackingCall).block();
        low.orchestrator().execute(lowCall).block();

        assertThat(JSON.readTree(conflict.bodies.get(0)).has("thinking")).isFalse();
        assertThat(conflictCall.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("OFF_WITH_EFFORT_NOT_ACCEPTED"));
        assertThat(conflictCall.getMetadata()).containsEntry("providerEffortRequested", "XHIGH");
        assertThat(lackingCall.getMetadata().get("providerThinkingAdjustment")).isEqualTo(List.of("EFFORT_NOT_SUPPORTED"));
        assertThat(JSON.readTree(low.bodies.get(0)).get("thinking").toString()).isEqualTo("{\"type\":\"disabled\"}");
        assertThat(lowCall.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("NOT_EXPRESSIBLE_SPRING_AI_1_1"));
        for (AnthropicServer server : List.of(conflict, lacking, low)) {
            assertThat(server.bodies.get(0)).doesNotContain("effort").doesNotContain("output_config");
        }
    }

    /**
     * T5: a 400 that names the thinking field the call sent (each of the Claude API's refusals Spring AI 1.1 can
     * provoke) is sent once more without it, with the allowance on the answer limit as the model's default is then
     * unknown; the model's later calls leave the field out from the start.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("thinkingRefusals")
    void aRefusedThinkingFieldIsSentOnceMoreWithoutIt(String model, String mode, String refusal) throws Exception {
        AnthropicServer server = new AnthropicServer(model);
        server.refuse(HttpStatus.BAD_REQUEST, refusal);
        server.answer();
        server.answer();
        ExecutionContext first = decisionCall(4096, settings(mode, 2048, 512));
        ExecutionContext later = decisionCall(4096, settings(mode, 2048, 512));

        String answer = server.orchestrator().execute(first).block();
        server.orchestrator().execute(later).block();

        assertThat(answer).isEqualTo("{\"action\":\"ALLOW\"}");
        assertThat(server.bodies).hasSize(3);
        assertThat(JSON.readTree(server.bodies.get(0)).has("thinking")).isTrue();
        JsonNode resent = JSON.readTree(server.bodies.get(1));
        assertThat(resent.has("thinking")).isFalse();
        assertThat(resent.get("max_tokens").asInt()).isEqualTo(4608);
        assertThat(first.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("PROVIDER_REJECTED_RESENT_WITHOUT_THINKING"));
        assertThat(first.getMetadata().get("providerRejectedFields")).isEqualTo(List.of("thinking"));
        assertThat(first.getMetadata()).doesNotContainKey("providerCallFailed");
        assertThat(JSON.readTree(server.bodies.get(2)).has("thinking")).isFalse();
        assertThat(later.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("PROVIDER_REJECTED_EARLIER_LEFT_OUT"));
    }

    static Stream<Arguments> thinkingRefusals() {
        return Stream.of(
                Arguments.of("claude-nova-enabled", "BUDGET", "\\\"thinking.type.enabled\\\" is not supported for this"
                        + " model. Use \\\"thinking.type.adaptive\\\" and \\\"output_config.effort\\\" to control thinking"
                        + " behavior."),
                Arguments.of("claude-nova-disabled", "OFF", "\\\"thinking.type.disabled\\\" is not supported for this"
                        + " model."),
                Arguments.of("claude-nova-disabled-effort", "OFF", "output_config.effort 'xhigh' is not supported when"
                        + " thinking is disabled on this model."));
    }

    /**
     * T5 (QF-51 extension): a 400 for the sampling a model newer than the sampling list refuses is sent once more
     * without any sampling value, Spring AI's default 0.8 included; the model's later calls carry none.
     */
    @Test
    void aRefusedSamplingValueIsSentOnceMoreWithoutSampling() throws Exception {
        AnthropicServer server = new AnthropicServer("claude-nova-sampling");
        server.refuse(HttpStatus.BAD_REQUEST, "`temperature` is deprecated for this model.");
        server.answer();
        server.answer();
        ExecutionContext first = decisionCall(4096, defaultSettings());
        ExecutionContext later = decisionCall(4096, defaultSettings());

        server.orchestrator().execute(first).block();
        server.orchestrator().execute(later).block();

        assertThat(JSON.readTree(server.bodies.get(0)).get("temperature").asDouble()).isEqualTo(0.0d);
        assertThat(JSON.readTree(server.bodies.get(1)).has("temperature")).isFalse();
        assertThat(JSON.readTree(server.bodies.get(2)).has("temperature")).isFalse();
        assertThat(first.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("PROVIDER_REJECTED_RESENT_WITHOUT_SAMPLING"));
        assertThat(first.getMetadata().get("providerRejectedFields")).isEqualTo(List.of("temperature"));
        assertThat(later.getMetadata().get("providerThinkingAdjustment"))
                .isEqualTo(List.of("PROVIDER_REJECTED_EARLIER_LEFT_OUT"));
    }

    /**
     * T5: a 400 that names no field the call sent, and a rate limit that names the thinking field, are not sent again
     * by the safety net: one request, and the failure is today's.
     */
    @Test
    void aRefusalOfSomethingElseIsNotSentAgain() {
        AnthropicServer other = new AnthropicServer("claude-nova-other");
        other.refuse(HttpStatus.BAD_REQUEST, "messages: text content blocks must be non-empty");
        AnthropicServer limited = new AnthropicServer("claude-nova-limited");
        limited.refuse(HttpStatus.TOO_MANY_REQUESTS, "rate limit for requests with thinking reached");
        Map<String, Object> noRetries = settings("BUDGET", 2048, 0);
        noRetries.put("disableRetries", true);

        assertThatThrownBy(() -> other.orchestrator().execute(decisionCall(4096, settings("BUDGET", 2048, 0))).block())
                .hasMessageContaining("400");
        assertThatThrownBy(() -> limited.orchestrator().execute(decisionCall(4096, noRetries)).block())
                .hasMessageContaining("429");

        assertThat(other.bodies).hasSize(1);
        assertThat(limited.bodies).hasSize(1);
        other.server.verify();
        limited.server.verify();
    }

    /** T5: a resend refused again fails as today, and nothing is kept: the model's next call sends the field again. */
    @Test
    void aResendRefusedAgainKeepsNothing() throws Exception {
        AnthropicServer server = new AnthropicServer("claude-nova-twice");
        String refusal = "\\\"thinking.type.disabled\\\" is not supported for this model.";
        server.refuse(HttpStatus.BAD_REQUEST, refusal);
        server.refuse(HttpStatus.BAD_REQUEST, "max_tokens: must be at most 1");
        server.answer();
        ExecutionContext first = decisionCall(4096, settings("OFF", null, 0));

        assertThatThrownBy(() -> server.orchestrator().execute(first).block()).hasMessageContaining("400");
        server.orchestrator().execute(decisionCall(4096, settings("OFF", null, 0))).block();

        assertThat(server.bodies).hasSize(3);
        assertThat(JSON.readTree(server.bodies.get(1)).has("thinking")).isFalse();
        assertThat(JSON.readTree(server.bodies.get(2)).get("thinking").toString()).isEqualTo("{\"type\":\"disabled\"}");
        assertThat(first.getMetadata()).containsEntry("providerCallFailed", true);
    }

    /**
     * T5: the resend stays within the call's time limit: it gets what the refused request left of it, not a new limit.
     * The provider takes 600 ms to refuse and 700 ms to answer under a 1,000 ms limit, so the resend times out where a
     * new limit would have let it answer.
     */
    @Test
    void theResendGetsWhatIsLeftOfTheCallsTimeLimit() {
        AnthropicServer server = new AnthropicServer("claude-nova-slow");
        server.expectAfter(600, withStatus(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON)
                .body("{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":"
                        + "\"\\\"thinking.type.disabled\\\" is not supported for this model.\"}}"));
        server.expectAfter(700, withSuccess(ANSWER, MediaType.APPLICATION_JSON));
        Map<String, Object> settings = settings("OFF", null, 0);
        settings.put("callTimeoutMs", 1000L);
        settings.put("disableRetries", true);
        ExecutionContext call = decisionCall(4096, settings);

        assertThatThrownBy(() -> server.orchestrator().execute(call).block()).hasMessageContaining("timeout");

        assertThat(server.bodies).hasSize(2);
        assertThat(call.getMetadata()).containsEntry("providerCallFailureCategory", "PROVIDER_CALL_TIMEOUT");
    }

    private static String firstBody(String model, int answerLimit, Map<String, Object> settings) {
        AnthropicServer server = new AnthropicServer(model);
        server.answer();
        server.orchestrator().execute(decisionCall(answerLimit, settings)).block();
        return server.bodies.get(0);
    }

    private static Map<String, Object> defaultSettings() {
        return settings("PROVIDER_DEFAULT", null, 0);
    }

    private static Map<String, Object> settings(String mode, Integer budget, int allowance) {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("anthropicThinking", mode);
        if (budget != null) {
            settings.put("anthropicThinkingBudgetTokens", budget);
        }
        settings.put("anthropicThinkingAllowanceTokens", allowance);
        return settings;
    }

    /** A security decision's model call as the pipeline step builds it: the platform's limit and determinism. */
    private static ExecutionContext decisionCall(int answerLimit, Map<String, Object> settings) {
        ExecutionContext context = ExecutionContext.from(
                new Prompt(List.of(new SystemMessage("system rules"), new UserMessage("decide"))));
        context.setRequestId("anthropic-thinking-body");
        context.setMaxTokens(answerLimit);
        context.setTemperature(0.0d);
        context.setSeed(1);
        context.setTier(1);
        settings.forEach(context::addMetadata);
        return context;
    }

    /** Spring AI 1.1.8's Anthropic model over a mock HTTP server that keeps every request body. */
    private static final class AnthropicServer {

        private final List<String> bodies = new ArrayList<>();
        private final MockRestServiceServer server;
        private final AnthropicChatModel model;

        private AnthropicServer(String modelId) {
            this(AnthropicChatOptions.builder().model(modelId).maxTokens(500).temperature(0.8d).build());
        }

        private AnthropicServer(AnthropicChatOptions defaults) {
            RestClient.Builder builder = RestClient.builder();
            this.server = MockRestServiceServer.bindTo(builder).build();
            AnthropicApi api = AnthropicApi.builder().apiKey("test").restClientBuilder(builder).build();
            this.model = AnthropicChatModel.builder()
                    .anthropicApi(api)
                    .defaultOptions(defaults)
                    .retryTemplate(RetryUtils.SHORT_RETRY_TEMPLATE)
                    .build();
        }

        private void answer() {
            expect(withSuccess(ANSWER, MediaType.APPLICATION_JSON));
        }

        private void refuse(HttpStatus status, String message) {
            expect(withStatus(status).contentType(MediaType.APPLICATION_JSON)
                    .body("{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\""
                            + message + "\"}}"));
        }

        private void expectAfter(long delayMs, ResponseCreator response) {
            expect(request -> {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted", ex);
                }
                return response.createResponse(request);
            });
        }

        private void expect(ResponseCreator response) {
            server.expect(requestTo(MESSAGES_URL))
                    .andExpect(request -> bodies.add(((MockClientHttpRequest) request).getBodyAsString()))
                    .andRespond(response);
        }

        private UnifiedLLMOrchestrator orchestrator() {
            ChatModel selected = model;
            ModelSelectionStrategy selection = new ModelSelectionStrategy() {
                @Override
                public ChatModel selectModel(ExecutionContext context) {
                    return selected;
                }

                @Override
                public Set<String> getSupportedModels() {
                    return Set.of();
                }

                @Override
                public boolean isModelAvailable(String modelName) {
                    return true;
                }
            };
            return new UnifiedLLMOrchestrator(selection, null, new TieredLLMProperties(), new AdvisorRegistry(),
                    new SecurityPlaneProperties());
        }
    }
}
