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

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.infra.ContexaReactorResources;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SingleThreadEventLoop;
import io.netty.handler.timeout.ReadTimeoutException;
import io.netty.util.concurrent.EventExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.http.client.HttpClientAutoConfiguration;
import org.springframework.boot.autoconfigure.http.client.reactive.ClientHttpConnectorAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import reactor.netty.http.HttpResources;
import reactor.netty.resources.LoopResources;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What Contexa's model calls answer, and how they fail, on a real application context and over real HTTP to an Ollama server on
 * this machine. These hold before and after Contexa's clients were given an event loop of their own: the answer, the application's
 * read timeout ({@code spring.http.client.read-timeout}) on a call, a server that closes the connection, and the time limit of a
 * stream.
 */
@Timeout(120)
class ContexaModelCallBehaviourTest {

    private FakeOllamaServer model;

    @BeforeEach
    void startTheModelServer() throws Exception {
        model = new FakeOllamaServer();
    }

    @AfterEach
    void stopTheModelServer() {
        model.close();
    }

    private ApplicationContextRunner contexa(String... settings) {
        List<String> properties = new ArrayList<>(List.of(
                "contexa.llm.chat.ollama.base-url=" + model.baseUrl(),
                "contexa.llm.chat.ollama.model=qwen3:8b",
                "contexa.llm.embedding.ollama.model=mxbai-embed-large",
                "contexa.llm.selection.chat.priority=ollama",
                "contexa.llm.selection.embedding.priority=ollama"));
        properties.addAll(List.of(settings));
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class,
                        HttpClientAutoConfiguration.class, RestClientAutoConfiguration.class, ClientHttpConnectorAutoConfiguration.class,
                        WebClientAutoConfiguration.class, CoreLLMTieredAutoConfiguration.class))
                .withUserConfiguration(ContexaBeans.class)
                .withPropertyValues(properties.toArray(new String[0]));
    }

    @Test
    void aChatAStreamAndAnEmbeddingAnswerAsBefore() {
        contexa().run(context -> {
            UnifiedLLMOrchestrator orchestrator = context.getBean(UnifiedLLMOrchestrator.class);

            assertThat(orchestrator.execute(ExecutionContext.from(new Prompt("decide"))).block(Duration.ofSeconds(30))).isEqualTo("ALLOW");
            List<String> chunks = orchestrator.stream(ExecutionContext.builder().prompt(new Prompt("decide")).timeoutMs(10_000).build())
                    .collectList().block(Duration.ofSeconds(30));
            assertThat(String.join("", chunks)).contains("ALLOW");
            float[] vector = context.getBean("contexaPrimaryEmbeddingModel", EmbeddingModel.class).embed("a text");
            assertThat(vector).containsExactly(0.25f, 0.5f, 0.75f);
        });
    }

    @Test
    void theApplicationsReadTimeoutStillEndsACallToASlowServer() {
        model.behave(FakeOllamaServer.Behaviour.SLOW, 3_000L);
        contexa("spring.http.client.read-timeout=300ms").run(context -> {
            OllamaApi api = context.getBean("contexaOllamaChatApi", OllamaApi.class);

            long started = System.nanoTime();
            assertThatThrownBy(() -> api.chat(chatRequest()))
                    .isInstanceOf(ResourceAccessException.class)
                    .hasRootCauseInstanceOf(ReadTimeoutException.class);
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isLessThan(2_500L);
        });
    }

    @Test
    void anEmbeddingOfAServerThatClosesTheConnectionFailsAsBefore() {
        model.behave(FakeOllamaServer.Behaviour.CLOSE, 0L);
        contexa().run(context -> {
            OllamaApi api = context.getBean("contexaOllamaChatApi", OllamaApi.class);

            assertThatThrownBy(() -> api.embed(new OllamaApi.EmbeddingsRequest("mxbai-embed-large", "a text")))
                    .isInstanceOf(ResourceAccessException.class)
                    .hasMessageContaining("Connection prematurely closed BEFORE response");
        });
    }

    @Test
    void aStreamFromASlowServerEndsAtItsTimeLimitAsBefore() {
        model.behave(FakeOllamaServer.Behaviour.SLOW, 3_000L);
        contexa().run(context -> {
            UnifiedLLMOrchestrator orchestrator = context.getBean(UnifiedLLMOrchestrator.class);
            ExecutionContext streamed = ExecutionContext.builder().prompt(new Prompt("decide")).timeoutMs(300).build();

            long started = System.nanoTime();
            assertThatThrownBy(() -> orchestrator.stream(streamed).collectList().block(Duration.ofSeconds(30)))
                    .hasRootCauseInstanceOf(TimeoutException.class);
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isLessThan(2_500L);
        });
    }

    /**
     * An application without Boot's RestClient builder: the call takes the request factory RestClient.builder() picks, Spring's
     * own Reactor Netty client, and makes its connection on Contexa's event loop and not on the JVM's.
     */
    @Test
    void anApplicationWithoutBootsRestClientBuilderCallsOnContexasEventLoop() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class,
                        ClientHttpConnectorAutoConfiguration.class, WebClientAutoConfiguration.class, CoreLLMTieredAutoConfiguration.class))
                .withUserConfiguration(ContexaBeans.class)
                .withPropertyValues("contexa.llm.chat.ollama.base-url=" + model.baseUrl(), "contexa.llm.chat.ollama.model=qwen3:8b",
                        "contexa.llm.selection.chat.priority=ollama", "contexa.llm.selection.embedding.priority=ollama")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(RestClient.Builder.class);
                    OllamaApi api = context.getBean("contexaOllamaChatApi", OllamaApi.class);
                    int onTheJvmsLoop = channels(HttpResources.get());
                    int onContexasLoop = channels(ContexaReactorResources.eventLoops());

                    assertThat(api.chat(chatRequest()).message().content()).isEqualTo("ALLOW");

                    assertThat(channels(ContexaReactorResources.eventLoops())).isGreaterThan(onContexasLoop);
                    assertThat(channels(HttpResources.get())).isEqualTo(onTheJvmsLoop);
                });
    }

    private static int channels(LoopResources resources) {
        EventLoopGroup group = resources.onClient(LoopResources.DEFAULT_NATIVE);
        int channels = 0;
        for (EventExecutor executor : group) {
            if (executor instanceof SingleThreadEventLoop loop) {
                channels += loop.registeredChannels();
            }
        }
        return channels;
    }

    private static OllamaApi.ChatRequest chatRequest() {
        return OllamaApi.ChatRequest.builder("qwen3:8b")
                .messages(List.of(OllamaApi.Message.builder(OllamaApi.Message.Role.USER).content("decide").build()))
                .stream(false)
                .build();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(ContexaProperties.class)
    static class ContexaBeans {

        @Bean
        AdvisorRegistry contexaAdvisorRegistry() {
            return new AdvisorRegistry();
        }

        @Bean
        JsonStreamingProcessor contexaJsonStreamingProcessor() {
            return new JsonStreamingProcessor();
        }
    }
}
