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

import io.contexa.contexacore.std.llm.gate.ModelCallScope;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * K148: the application's OpenAI and Anthropic chat models, as Spring AI builds them from the application's RestClient
 * builder, with a blocking request factory of the application's (simple() here: Apache HttpClient 5 and Jetty do not
 * resolve offline, and read the same blocking way): a model call of Contexa given up at its time limit, as
 * UnifiedLLMOrchestrator gives it up (in ModelCallScope, future.get, then cancel(true)), closes its connection then and the
 * slow server writes none of its answer; a request of the application's own keeps the application's factory, and an
 * application on Reactor Netty is left as it is.
 */
class ModelCallTransportCustomizerTest {

    /** The answer starts this long after the server took the connection. */
    private static final long ANSWER_AFTER_MS = 6_000;
    /** The time limit of the call; it holds a first call's warm-up of the model client too. */
    private static final long LIMIT_MS = 2_000;

    record Seen(long closedAt, int written) {
    }

    @Test
    void anOpenAiModelOfTheApplicationIsCutAtContexasLimit() throws Exception {
        assertCut(base -> OpenAiChatModel.builder()
                .openAiApi(OpenAiApi.builder().baseUrl(base).apiKey("k").restClientBuilder(applicationBuilder(null)).build())
                .defaultOptions(OpenAiChatOptions.builder().model("m").build()).build());
    }

    @Test
    void anAnthropicModelOfTheApplicationIsCutAtContexasLimit() throws Exception {
        assertCut(base -> AnthropicChatModel.builder()
                .anthropicApi(AnthropicApi.builder().baseUrl(base).apiKey("k").restClientBuilder(applicationBuilder(null))
                        .build())
                .defaultOptions(AnthropicChatOptions.builder().model("m").maxTokens(10).build()).build());
    }

    @Test
    void aRequestOfTheApplicationsOwnKeepsTheApplicationsFactory() throws Exception {
        ClientHttpRequestFactory factory = requestFactoryOf(applicationBuilder(null));
        URI uri = URI.create("http://127.0.0.1:1/x");

        assertThat(factory).isInstanceOf(ModelCallRequestFactory.class);
        assertThat(factory.createRequest(uri, HttpMethod.GET).getClass().getSimpleName()).startsWith("Simple");
        assertThat(ModelCallScope.call(() -> factory.createRequest(uri, HttpMethod.GET)).getClass().getSimpleName())
                .startsWith("Reactor");
    }

    @Test
    void anApplicationOnReactorNettyIsLeftAsItIs() throws Exception {
        RestClient.Builder builder = RestClient.builder();
        customizer(ClientHttpRequestFactoryBuilder.reactor(), null).customize(builder);

        assertThat(requestFactoryOf(builder)).isNotInstanceOf(ModelCallRequestFactory.class);
    }

    @Test
    void theApplicationsReadTimeoutAppliesToContexasCalls() throws Exception {
        RestClient.Builder builder = applicationBuilder(ClientHttpRequestFactorySettings.defaults()
                .withReadTimeout(Duration.ofMillis(500)));
        try (ServerSocket server = new ServerSocket(0)) {
            ExecutorService serverThread = Executors.newSingleThreadExecutor();
            long start = System.currentTimeMillis();
            Future<Seen> seen = serverThread.submit(() -> serve(server, start));
            RestClient client = builder.build();
            assertThatThrownBy(() -> ModelCallScope.call(() -> client.get()
                    .uri("http://127.0.0.1:" + server.getLocalPort() + "/x").retrieve().body(String.class)))
                    .isInstanceOf(RuntimeException.class);
            Seen result = seen.get(20, TimeUnit.SECONDS);
            assertThat(result.closedAt()).as("closed by the read timeout").isBetween(400L, 3_000L);
            assertThat(result.written()).isZero();
            serverThread.shutdownNow();
        }
    }

    /** The application's builder as Boot makes it, its customizers applied: Contexa's runs on its blocking factory. */
    private static RestClient.Builder applicationBuilder(ClientHttpRequestFactorySettings settings) {
        ClientHttpRequestFactoryBuilder<?> factories = ClientHttpRequestFactoryBuilder.simple();
        RestClient.Builder builder = RestClient.builder().requestFactory(factories.build(
                settings != null ? settings : ClientHttpRequestFactorySettings.defaults()));
        customizer(factories, settings).customize(builder);
        return builder;
    }

    private static RestClientCustomizer customizer(ClientHttpRequestFactoryBuilder<?> factories,
                                                   ClientHttpRequestFactorySettings settings) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("clientHttpRequestFactoryBuilder", factories);
        if (settings != null) {
            beans.addBean("clientHttpRequestFactorySettings", settings);
        }
        return new CoreLLMTieredAutoConfiguration().contexaModelCallTransportCustomizer(factoryBuilders(beans),
                beans.getBeanProvider(ClientHttpRequestFactorySettings.class));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static ObjectProvider<ClientHttpRequestFactoryBuilder<?>> factoryBuilders(StaticListableBeanFactory beans) {
        return (ObjectProvider) beans.getBeanProvider(ClientHttpRequestFactoryBuilder.class);
    }

    private static ClientHttpRequestFactory requestFactoryOf(RestClient.Builder builder) throws Exception {
        RestClient client = builder.build();
        Field field = client.getClass().getDeclaredField("clientRequestFactory");
        field.setAccessible(true);
        return (ClientHttpRequestFactory) field.get(client);
    }

    /** Contexa's call of the model given up at its limit: its connection closes then, the server writes no answer. */
    private static void assertCut(Function<String, ChatModel> model) throws Exception {
        try (ServerSocket server = new ServerSocket(0)) {
            ExecutorService serverThread = Executors.newSingleThreadExecutor();
            ExecutorService providerCall = Executors.newCachedThreadPool();
            ChatModel chat = model.apply("http://127.0.0.1:" + server.getLocalPort());
            long start = System.currentTimeMillis();
            Future<Seen> seen = serverThread.submit(() -> serve(server, start));
            Future<Object> call = providerCall.submit(() -> ModelCallScope.call(() -> chat.call(new Prompt("hello"))));
            assertThatThrownBy(() -> call.get(LIMIT_MS, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            call.cancel(true);
            long gaveUp = System.currentTimeMillis() - start;
            Seen result = seen.get(20, TimeUnit.SECONDS);
            System.out.println("K148 cut: gave up at " + gaveUp + " ms, server saw the close at " + result.closedAt()
                    + " ms, wrote " + result.written() + " bytes");
            assertThat(result.closedAt()).as("the server sees the connection close after the cut, before its answer")
                    .isBetween(1L, gaveUp + 1_000);
            assertThat(result.written()).as("bytes of the answer the server wrote").isZero();
            serverThread.shutdownNow();
            providerCall.shutdownNow();
        }
    }

    /** A server that answers after ANSWER_AFTER_MS, noting when the client closed the connection before it. */
    private static Seen serve(ServerSocket server, long start) throws Exception {
        server.setSoTimeout(15_000);
        try (Socket socket = server.accept()) {
            long accepted = System.currentTimeMillis();
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            byte[] buffer = new byte[16384];
            socket.setSoTimeout(300);
            try {
                while (in.read(buffer) > 0) {
                    // the request
                }
            } catch (SocketTimeoutException done) {
                // all of it read
            }
            socket.setSoTimeout(50);
            while (System.currentTimeMillis() < accepted + ANSWER_AFTER_MS) {
                try {
                    if (in.read() < 0) {
                        return new Seen(System.currentTimeMillis() - start, 0);
                    }
                } catch (SocketTimeoutException waiting) {
                    // still open
                } catch (IOException reset) {
                    return new Seen(System.currentTimeMillis() - start, 0);
                }
            }
            int written = 0;
            try {
                out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                        .getBytes(StandardCharsets.US_ASCII));
                for (int i = 0; i < 5; i++) {
                    String chunk = i == 0 ? "{\"id\":\"x\"," : "\"p" + i + "\":" + i + (i == 4 ? "}" : ",");
                    out.write((Integer.toHexString(chunk.length()) + "\r\n" + chunk + "\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    written += chunk.length();
                    Thread.sleep(100);
                }
                out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
            } catch (IOException gone) {
                // the client went while the answer was written
            }
            return new Seen(-1, written);
        }
    }
}
