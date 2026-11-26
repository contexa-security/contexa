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

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * R-9: a chat model the orchestrator is handed as the application has it (one Contexa could not make an instance of
 * its own of: a subclass, a wrapper, a copy that failed) keeps the default options the application gave it, whatever
 * Contexa's calls on it ask for: the default sampling of a model that takes no other, thinking on an older model, and
 * the resend after a provider refusal. The application's own call through the same model sends the body it sent before
 * Contexa called it. The real Spring AI 1.1.8 Anthropic model over a mock HTTP server; no provider is called.
 */
@DisplayName("Contexa 호출은 앱이 가진 그대로의 채팅 모델 기본 옵션을 바꾸지 않는다")
class ApplicationChatModelDefaultsTest {

    private static final String MESSAGES_URL = "https://api.anthropic.com/v1/messages";
    private static final String ANSWER = "{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\","
            + "\"model\":\"m\",\"content\":[{\"type\":\"text\",\"text\":\"{\\\"action\\\":\\\"ALLOW\\\"}\"}],"
            + "\"stop_reason\":\"end_turn\",\"stop_sequence\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}";

    @Test
    @DisplayName("기본 샘플링만 받는 모델로 Contexa가 호출해도 앱 모델의 기본 옵션과 앱 호출 본문은 그대로다")
    void aModelThatTakesOnlyTheDefaultSamplingKeepsTheApplicationsOptions() {
        ApplicationsModel application = new ApplicationsModel("claude-haiku-5-5");
        application.answer(3);

        String before = application.callItself();
        application.orchestrator().execute(decisionCall("PROVIDER_DEFAULT", null)).block();
        String after = application.callItself();

        assertThat(after).isEqualTo(before).contains("\"temperature\":0.8").contains("\"top_k\":5");
        assertThat(application.defaults().getTemperature()).isEqualTo(0.8d);
        assertThat(application.defaults().getTopK()).isEqualTo(5);
    }

    @Test
    @DisplayName("이전 모델의 생각 설정으로 Contexa가 호출해도 앱 모델의 온도는 그대로다")
    void thinkingOnAnOlderModelKeepsTheApplicationsTemperature() {
        ApplicationsModel application = new ApplicationsModel("claude-sonnet-4-6");
        application.answer(3);

        String before = application.callItself();
        application.orchestrator().execute(decisionCall("BUDGET", 2048)).block();
        String after = application.callItself();

        assertThat(after).isEqualTo(before).contains("\"temperature\":0.8");
        assertThat(application.defaults().getTemperature()).isEqualTo(0.8d);
        assertThat(application.defaults().getTopK()).isEqualTo(5);
    }

    @Test
    @DisplayName("제공자가 샘플링을 거절해 Contexa가 다시 보내도 앱 모델의 기본 옵션은 그대로다")
    void theResendAfterARefusalKeepsTheApplicationsOptions() {
        ApplicationsModel application = new ApplicationsModel("claude-nova-application-defaults");
        application.answer(1);
        application.refuse("`temperature` is deprecated for this model.");
        application.answer(2);

        String before = application.callItself();
        try {
            application.orchestrator().execute(decisionCall("PROVIDER_DEFAULT", null)).block();
        } catch (RuntimeException ignored) {
        }
        String after = application.callItself();

        assertThat(after).isEqualTo(before).contains("\"temperature\":0.8").contains("\"top_k\":5");
        assertThat(application.defaults().getTemperature()).isEqualTo(0.8d);
        assertThat(application.defaults().getTopK()).isEqualTo(5);
    }

    /** A security decision's model call as the pipeline step builds it, with the layer's thinking setting. */
    private static ExecutionContext decisionCall(String thinking, Integer budget) {
        ExecutionContext context = ExecutionContext.from(
                new Prompt(List.of(new SystemMessage("system rules"), new UserMessage("decide"))));
        context.setRequestId("application-defaults");
        context.setMaxTokens(4096);
        context.setTemperature(0.0d);
        context.setTier(1);
        context.addMetadata("anthropicThinking", thinking);
        if (budget != null) {
            context.addMetadata("anthropicThinkingBudgetTokens", budget);
        }
        context.addMetadata("anthropicThinkingAllowanceTokens", 0);
        context.addMetadata("disableRetries", true);
        return context;
    }

    /** The application's Spring AI 1.1.8 Anthropic model over a mock HTTP server that keeps every request body. */
    private static final class ApplicationsModel {

        private final List<String> bodies = new ArrayList<>();
        private final MockRestServiceServer server;
        private final AnthropicChatModel model;

        private ApplicationsModel(String modelId) {
            RestClient.Builder builder = RestClient.builder();
            this.server = MockRestServiceServer.bindTo(builder).build();
            AnthropicApi api = AnthropicApi.builder().apiKey("test").restClientBuilder(builder).build();
            this.model = AnthropicChatModel.builder()
                    .anthropicApi(api)
                    .defaultOptions(AnthropicChatOptions.builder().model(modelId).maxTokens(500).temperature(0.8d)
                            .topK(5).build())
                    .retryTemplate(RetryUtils.SHORT_RETRY_TEMPLATE)
                    .build();
        }

        private void answer(int times) {
            for (int i = 0; i < times; i++) {
                expect(withSuccess(ANSWER, MediaType.APPLICATION_JSON));
            }
        }

        private void refuse(String message) {
            expect(withStatus(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON)
                    .body("{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\""
                            + message + "\"}}"));
        }

        private void expect(ResponseCreator response) {
            server.expect(requestTo(MESSAGES_URL))
                    .andExpect(request -> bodies.add(((MockClientHttpRequest) request).getBodyAsString()))
                    .andRespond(response);
        }

        /** The application's own call through its model, with options of its own; the body it sent. */
        private String callItself() {
            int sent = bodies.size();
            model.call(new Prompt(List.of(new SystemMessage("You decide."), new UserMessage("hello")),
                    AnthropicChatOptions.builder().maxTokens(500).build()));
            return bodies.get(sent);
        }

        private AnthropicChatOptions defaults() {
            return (AnthropicChatOptions) model.getDefaultOptions();
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
