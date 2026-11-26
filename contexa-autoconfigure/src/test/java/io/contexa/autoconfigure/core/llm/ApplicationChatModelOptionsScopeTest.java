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
package io.contexa.autoconfigure.core.llm;

import com.sun.net.httpserver.HttpServer;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.ai.retry.RetryUtils;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * R-9: Contexa adjusts the default options of the chat model it calls for the model that runs (sampling values the
 * newest models refuse, the token limit field of OpenAI's reasoning models, the system prompt cache). It does so on an
 * instance of its own; the application's chat model beans keep the options the application gave them, and the
 * application's own calls send what they send without Contexa.
 */
@DisplayName("Spring AI 모델 옵션 조정은 Contexa 인스턴스에만 적용된다")
class ApplicationChatModelOptionsScopeTest {

    private static final String ANSWER = "{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\","
            + "\"model\":\"claude-haiku-5-5\",\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],"
            + "\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";

    private static ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(AnthropicChatModelOptionsAutoConfiguration.class,
                        OpenAiChatModelOptionsAutoConfiguration.class, CoreLLMTieredAutoConfiguration.class))
                .withBean(ContexaProperties.class)
                .withBean(AdvisorRegistry.class, () -> mock(AdvisorRegistry.class))
                .withBean(JsonStreamingProcessor.class, () -> mock(JsonStreamingProcessor.class));
    }

    private static AnthropicChatModel applicationsAnthropicModel(String baseUrl) {
        AnthropicApi.Builder api = AnthropicApi.builder().apiKey("test");
        if (baseUrl != null) {
            api.baseUrl(baseUrl);
        }
        return AnthropicChatModel.builder().anthropicApi(api.build())
                .defaultOptions(AnthropicChatOptions.builder().model("claude-haiku-5-5").temperature(0.8d).topK(5)
                        .maxTokens(500).build())
                .build();
    }

    private static OpenAiChatModel applicationsOpenAiModel() {
        return OpenAiChatModel.builder()
                .openAiApi(OpenAiApi.builder().apiKey("test").build())
                .defaultOptions(OpenAiChatOptions.builder().model("gpt-5-nano").temperature(0.7d).maxTokens(100).build())
                .build();
    }

    @Test
    @DisplayName("앱의 Anthropic 모델 빈은 Contexa가 있어도 앱이 준 기본 옵션 그대로다")
    void theApplicationsAnthropicModelKeepsItsOptions() {
        runner().withBean("anthropicChatModel", ChatModel.class, () -> applicationsAnthropicModel(null))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    context.getBean("contexaPrimaryChatModel");
                    AnthropicChatOptions defaults =
                            (AnthropicChatOptions) context.getBean("anthropicChatModel", ChatModel.class).getDefaultOptions();
                    assertThat(defaults.getTemperature()).isEqualTo(0.8d);
                    assertThat(defaults.getTopK()).isEqualTo(5);
                    assertThat(defaults.getCacheOptions() == null
                            || defaults.getCacheOptions().getStrategy() == AnthropicCacheStrategy.NONE).isTrue();
                });
    }

    @Test
    @DisplayName("앱의 OpenAI 모델 빈은 Contexa가 있어도 앱이 준 기본 옵션 그대로다")
    void theApplicationsOpenAiModelKeepsItsOptions() {
        runner().withPropertyValues("contexa.llm.selection.chat.priority=openai")
                .withBean("openAiChatModel", ChatModel.class, ApplicationChatModelOptionsScopeTest::applicationsOpenAiModel)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    context.getBean("contexaPrimaryChatModel");
                    OpenAiChatOptions defaults =
                            (OpenAiChatOptions) context.getBean("openAiChatModel", ChatModel.class).getDefaultOptions();
                    assertThat(defaults.getTemperature()).isEqualTo(0.7d);
                    assertThat(defaults.getMaxTokens()).isEqualTo(100);
                    assertThat(defaults.getMaxCompletionTokens()).isNull();
                });
    }

    @Test
    @DisplayName("Contexa가 부르는 Anthropic 모델은 앱 빈의 복사본이고 Contexa의 조정이 붙으며 앱의 클라이언트와 재시도를 그대로 쓴다")
    void contexaCallsACopyOfTheApplicationsAnthropicModel() {
        runner().withBean("anthropicChatModel", ChatModel.class, () -> applicationsAnthropicModel(null))
                .run(context -> {
                    ChatModel application = context.getBean("anthropicChatModel", ChatModel.class);
                    ChatModel contexas = context.getBean("contexaPrimaryChatModel", ChatModel.class);

                    assertThat(contexas).isInstanceOf(AnthropicChatModel.class).isNotSameAs(application);
                    AnthropicChatOptions defaults = (AnthropicChatOptions) contexas.getDefaultOptions();
                    assertThat(defaults.getModel()).isEqualTo("claude-haiku-5-5");
                    assertThat(defaults.getTemperature()).isNull();
                    assertThat(defaults.getTopK()).isNull();
                    assertThat(defaults.getMaxTokens()).isEqualTo(500);
                    assertThat(defaults.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.SYSTEM_ONLY);
                    assertThat(ReflectionTestUtils.getField(contexas, "anthropicApi"))
                            .isSameAs(ReflectionTestUtils.getField(application, "anthropicApi"));
                    assertThat(ReflectionTestUtils.getField(contexas, "retryTemplate"))
                            .isSameAs(ReflectionTestUtils.getField(application, "retryTemplate"));
                });
    }

    @Test
    @DisplayName("Contexa가 부르는 OpenAI 모델은 앱 빈의 복사본이고 추론 모델의 토큰 한도 필드와 샘플링 조정이 복사본에만 붙는다")
    void contexaCallsACopyOfTheApplicationsOpenAiModel() {
        runner().withPropertyValues("contexa.llm.selection.chat.priority=openai")
                .withBean("openAiChatModel", ChatModel.class, ApplicationChatModelOptionsScopeTest::applicationsOpenAiModel)
                .run(context -> {
                    ChatModel application = context.getBean("openAiChatModel", ChatModel.class);
                    ChatModel contexas = context.getBean("contexaPrimaryChatModel", ChatModel.class);

                    assertThat(contexas).isInstanceOf(OpenAiChatModel.class).isNotSameAs(application);
                    OpenAiChatOptions defaults = (OpenAiChatOptions) contexas.getDefaultOptions();
                    assertThat(defaults.getModel()).isEqualTo("gpt-5-nano");
                    assertThat(defaults.getTemperature()).isNull();
                    assertThat(defaults.getMaxTokens()).isNull();
                    assertThat(defaults.getMaxCompletionTokens()).isEqualTo(100);
                    assertThat(ReflectionTestUtils.getField(contexas, "openAiApi"))
                            .isSameAs(ReflectionTestUtils.getField(application, "openAiApi"));
                });
    }

    /**
     * What goes over the wire: the application's call through its own bean, with options of its own, sends the
     * temperature it set and marks no cache, as without Contexa; Contexa's call, with the options Contexa builds from the
     * model it calls, sends no sampling value and marks the system prompt.
     */
    @Test
    @DisplayName("앱의 호출 본문은 Contexa가 없을 때와 같고 Contexa의 호출 본문에만 조정이 실린다")
    void onlyContexasCallCarriesTheAdjustment() throws Exception {
        List<String> bodies = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] answer = ANSWER.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, answer.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(answer);
            }
        });
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            runner().withBean("anthropicChatModel", ChatModel.class, () -> applicationsAnthropicModel(baseUrl))
                    .run(context -> {
                        List<Message> messages = List.of(new SystemMessage("You decide."), new UserMessage("hello"));
                        context.getBean("anthropicChatModel", ChatModel.class)
                                .call(new Prompt(messages, AnthropicChatOptions.builder().maxTokens(500).build()));
                        ChatModel contexas = context.getBean("contexaPrimaryChatModel", ChatModel.class);
                        Prompt prompt = new Prompt(messages);
                        contexas.call(new Prompt(messages, ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                                ExecutionContext.from(prompt), contexas)));
                    });
        } finally {
            server.stop(0);
        }

        assertThat(bodies).hasSize(2);
        assertThat(bodies.get(0)).as("the application's call").contains("\"temperature\":0.8")
                .doesNotContain("cache_control");
        assertThat(bodies.get(1)).as("Contexa's call").doesNotContain("\"temperature\"").contains("cache_control");
    }

    /**
     * A subclass of the provider's model is no class Contexa makes a copy of: Contexa calls the application's bean as it
     * is. Its calls through Contexa's orchestrator, the path that took the refused defaults out of the model they were
     * handed, leave the bean's default options as the application gave them, and the application's own call sends the
     * body it sends without Contexa; Contexa's call carries what Contexa asks for in its request.
     */
    @Test
    @DisplayName("복사할 수 없는 앱 Anthropic 하위 클래스 모델도 Contexa 호출 뒤 앱 호출 본문이 Contexa가 없을 때와 같다")
    void anApplicationsAnthropicSubclassSendsTheBodyOfWithoutContexa() throws Exception {
        FakeProviders providers = FakeProviders.start();
        try {
            String withoutContexa = providers.callAnthropic(providers.applicationsAnthropicSubclass());
            List<String> inContext = new ArrayList<>();
            runner().withBean("anthropicChatModel", ChatModel.class, providers::applicationsAnthropicSubclass)
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        ChatModel application = context.getBean("anthropicChatModel", ChatModel.class);
                        assertThat(context.getBean("contexaPrimaryChatModel", ChatModel.class)).isSameAs(application);
                        inContext.add(providers.callAnthropic(application));
                        contexasCall(context.getBean(UnifiedLLMOrchestrator.class));
                        inContext.add(providers.bodies.get(providers.bodies.size() - 1));
                        inContext.add(providers.callAnthropic(application));
                        AnthropicChatOptions defaults = (AnthropicChatOptions) application.getDefaultOptions();
                        assertThat(defaults.getTemperature()).isEqualTo(0.8d);
                        assertThat(defaults.getTopK()).isEqualTo(5);
                    });

            assertThat(inContext).hasSize(3);
            assertThat(inContext.get(0)).as("the application's call before Contexa's").isEqualTo(withoutContexa);
            assertThat(inContext.get(2)).as("the application's call after Contexa's").isEqualTo(withoutContexa);
            assertThat(inContext.get(1)).as("Contexa's call").contains("\"max_tokens\":300");
        } finally {
            providers.stop();
        }
    }

    @Test
    @DisplayName("복사할 수 없는 앱 OpenAI 하위 클래스 모델도 Contexa 호출 뒤 앱 호출 본문이 Contexa가 없을 때와 같다")
    void anApplicationsOpenAiSubclassSendsTheBodyOfWithoutContexa() throws Exception {
        FakeProviders providers = FakeProviders.start();
        try {
            String withoutContexa = providers.callOpenAi(providers.applicationsOpenAiSubclass());
            List<String> inContext = new ArrayList<>();
            runner().withPropertyValues("contexa.llm.selection.chat.priority=openai")
                    .withBean("openAiChatModel", ChatModel.class, providers::applicationsOpenAiSubclass)
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        ChatModel application = context.getBean("openAiChatModel", ChatModel.class);
                        assertThat(context.getBean("contexaPrimaryChatModel", ChatModel.class)).isSameAs(application);
                        inContext.add(providers.callOpenAi(application));
                        contexasCall(context.getBean(UnifiedLLMOrchestrator.class));
                        inContext.add(providers.bodies.get(providers.bodies.size() - 1));
                        inContext.add(providers.callOpenAi(application));
                        OpenAiChatOptions defaults = (OpenAiChatOptions) application.getDefaultOptions();
                        assertThat(defaults.getTemperature()).isEqualTo(0.7d);
                        assertThat(defaults.getMaxTokens()).isEqualTo(100);
                        assertThat(defaults.getMaxCompletionTokens()).isNull();
                    });

            assertThat(inContext).hasSize(3);
            assertThat(inContext.get(0)).as("the application's call before Contexa's").isEqualTo(withoutContexa);
            assertThat(inContext.get(2)).as("the application's call after Contexa's").isEqualTo(withoutContexa);
            assertThat(inContext.get(1)).as("Contexa's call").contains("\"max_completion_tokens\":300");
        } finally {
            providers.stop();
        }
    }

    /** A call of Contexa's engine as its pipeline makes one: an answer limit, a temperature, no retry. */
    private static void contexasCall(UnifiedLLMOrchestrator orchestrator) {
        ExecutionContext call = ExecutionContext.from(
                new Prompt(List.of(new SystemMessage("You decide."), new UserMessage("hello"))));
        call.setRequestId("application-subclass");
        call.setMaxTokens(300);
        call.setTemperature(0.0d);
        call.addMetadata("disableRetries", true);
        orchestrator.execute(call).block();
    }

    /** An application's Anthropic model of a class of its own. */
    static final class ApplicationsAnthropicModel extends AnthropicChatModel {

        ApplicationsAnthropicModel(AnthropicApi api, AnthropicChatOptions options) {
            super(api, options, ToolCallingManager.builder().build(), RetryUtils.DEFAULT_RETRY_TEMPLATE,
                    ObservationRegistry.NOOP);
        }
    }

    /** An application's OpenAI model of a class of its own. */
    static final class ApplicationsOpenAiModel extends OpenAiChatModel {

        ApplicationsOpenAiModel(OpenAiApi api, OpenAiChatOptions options) {
            super(api, options, ToolCallingManager.builder().build(), RetryUtils.DEFAULT_RETRY_TEMPLATE,
                    ObservationRegistry.NOOP);
        }
    }

    /** One local HTTP server answering as Anthropic's messages API and OpenAI's chat completions API; it keeps bodies. */
    private static final class FakeProviders {

        private static final String OPENAI_ANSWER = "{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion\",\"created\":1,"
                + "\"model\":\"gpt-5-nano\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\","
                + "\"content\":\"ok\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,"
                + "\"completion_tokens\":1,\"total_tokens\":2}}";

        private final List<String> bodies = new CopyOnWriteArrayList<>();
        private final HttpServer server;

        private FakeProviders(HttpServer server) {
            this.server = server;
        }

        static FakeProviders start() throws Exception {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            FakeProviders providers = new FakeProviders(server);
            server.createContext("/", exchange -> {
                providers.bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                boolean openAi = exchange.getRequestURI().getPath().endsWith("/chat/completions");
                byte[] answer = (openAi ? OPENAI_ANSWER : ANSWER).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, answer.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(answer);
                }
            });
            server.start();
            return providers;
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        ApplicationsAnthropicModel applicationsAnthropicSubclass() {
            return new ApplicationsAnthropicModel(AnthropicApi.builder().apiKey("test").baseUrl(baseUrl()).build(),
                    AnthropicChatOptions.builder().model("claude-haiku-5-5").temperature(0.8d).topK(5).maxTokens(500)
                            .build());
        }

        ApplicationsOpenAiModel applicationsOpenAiSubclass() {
            return new ApplicationsOpenAiModel(OpenAiApi.builder().apiKey("test").baseUrl(baseUrl()).build(),
                    OpenAiChatOptions.builder().model("gpt-5-nano").temperature(0.7d).maxTokens(100).build());
        }

        /** The application's own call through its model, with options of its own; the body it sent. */
        String callAnthropic(ChatModel model) {
            int sent = bodies.size();
            model.call(new Prompt(List.of(new SystemMessage("You decide."), new UserMessage("hello")),
                    AnthropicChatOptions.builder().maxTokens(500).build()));
            return bodies.get(sent);
        }

        String callOpenAi(ChatModel model) {
            int sent = bodies.size();
            model.call(new Prompt(List.of(new SystemMessage("You decide."), new UserMessage("hello")),
                    OpenAiChatOptions.builder().maxTokens(100).build()));
            return bodies.get(sent);
        }

        void stop() {
            server.stop(0);
        }
    }
}
