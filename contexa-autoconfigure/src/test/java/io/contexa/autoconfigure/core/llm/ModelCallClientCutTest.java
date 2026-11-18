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

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ReactorClientHttpRequestFactory;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * K145: a model call takes Reactor Netty with or without the application's builder and whatever the application's request
 * factory builder is (a blocking one here, as Apache HttpClient and Jetty are): a call given up at
 * its time limit, as UnifiedLLMOrchestrator gives it up (future.get, then cancel(true)), closes its connection at once and
 * the slow server writes none of its answer. The application's settings (a read timeout) still apply.
 */
class ModelCallClientCutTest {

    private static final long ANSWER_AFTER_MS = 4_000;
    private static final long LIMIT_MS = 1_000;

    record Seen(long closedAt, int written) {
    }

    @Test
    void withTheApplicationsBuilderAndTheFactoryBootDetectsAModelCallIsCutAtItsLimit() throws Exception {
        RestClient.Builder builder = modelCallBuilder(RestClient.builder(), null, null);

        assertThat(requestFactoryOf(builder)).isInstanceOf(ReactorClientHttpRequestFactory.class);
        assertCut(builder);
    }

    @Test
    void withAnotherFactoryThanApachesAModelCallIsCutAtItsLimit() throws Exception {
        RestClient.Builder builder = modelCallBuilder(RestClient.builder(), ClientHttpRequestFactoryBuilder.simple(), null);

        assertThat(requestFactoryOf(builder)).isInstanceOf(ReactorClientHttpRequestFactory.class);
        assertCut(builder);
    }

    @Test
    void withoutTheApplicationsBuilderAModelCallIsCutAtItsLimit() throws Exception {
        RestClient.Builder builder = modelCallBuilder(null, null, null);

        assertThat(requestFactoryOf(builder)).isInstanceOf(ReactorClientHttpRequestFactory.class);
        assertCut(builder);
    }

    @Test
    void theApplicationsReadTimeoutStillApplies() throws Exception {
        RestClient.Builder builder = modelCallBuilder(RestClient.builder(), ClientHttpRequestFactoryBuilder.simple(),
                ClientHttpRequestFactorySettings.defaults().withReadTimeout(Duration.ofMillis(500)));

        try (ServerSocket server = new ServerSocket(0)) {
            ExecutorService serverThread = Executors.newSingleThreadExecutor();
            long start = System.currentTimeMillis();
            Future<Seen> seen = serverThread.submit(() -> serve(server, start));
            RestClient client = builder.build();
            assertThatThrownBy(() -> client.post().uri("http://127.0.0.1:" + server.getLocalPort() + "/api/chat")
                    .body("{\"model\":\"m\"}").retrieve().body(String.class)).isInstanceOf(ResourceAccessException.class);
            Seen result = seen.get(20, TimeUnit.SECONDS);
            assertThat(result.closedAt()).as("closed by the read timeout").isBetween(400L, ANSWER_AFTER_MS - 1);
            assertThat(result.written()).isZero();
            serverThread.shutdownNow();
        }
    }

    private static RestClient.Builder modelCallBuilder(RestClient.Builder application,
                                                       ClientHttpRequestFactoryBuilder<?> factories,
                                                       ClientHttpRequestFactorySettings settings) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        if (application != null) {
            beans.addBean("restClientBuilder", application);
        }
        if (factories != null) {
            beans.addBean("clientHttpRequestFactoryBuilder", factories);
        }
        if (settings != null) {
            beans.addBean("clientHttpRequestFactorySettings", settings);
        }
        return CoreLLMTieredAutoConfiguration.OllamaConfiguration.modelCallRestClient(
                beans.getBeanProvider(RestClient.Builder.class),
                factoryBuilders(beans),
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

    /** The call given up at its limit closes its connection then, and the server writes none of its answer. */
    private static void assertCut(RestClient.Builder builder) throws Exception {
        try (ServerSocket server = new ServerSocket(0)) {
            ExecutorService serverThread = Executors.newSingleThreadExecutor();
            ExecutorService providerCall = Executors.newCachedThreadPool();
            long start = System.currentTimeMillis();
            Future<Seen> seen = serverThread.submit(() -> serve(server, start));
            RestClient client = builder.build();
            Future<String> call = providerCall.submit(() -> client.post()
                    .uri("http://127.0.0.1:" + server.getLocalPort() + "/api/chat").body("{\"model\":\"m\"}")
                    .retrieve().body(String.class));
            assertThatThrownBy(() -> call.get(LIMIT_MS, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            call.cancel(true);
            long gaveUp = System.currentTimeMillis() - start;
            Seen result = seen.get(20, TimeUnit.SECONDS);
            System.out.println("K145 cut: gave up at " + gaveUp + " ms, server saw the close at " + result.closedAt()
                    + " ms, wrote " + result.written() + " bytes");
            assertThat(result.closedAt()).as("the server sees the connection close after the cut, before its answer")
                    .isBetween(LIMIT_MS - 100, gaveUp + 1_000);
            assertThat(result.written()).as("bytes of the answer the server wrote").isZero();
            serverThread.shutdownNow();
            providerCall.shutdownNow();
        }
    }

    /** A server that answers after ANSWER_AFTER_MS, noting when the client closed the connection before it. */
    private static Seen serve(ServerSocket server, long start) throws Exception {
        try (Socket socket = server.accept()) {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            byte[] buffer = new byte[8192];
            socket.setSoTimeout(300);
            try {
                while (in.read(buffer) > 0) {
                    // the request
                }
            } catch (SocketTimeoutException done) {
                // all of it read
            }
            socket.setSoTimeout(50);
            while (System.currentTimeMillis() < start + ANSWER_AFTER_MS) {
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
                out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                for (int i = 0; i < 5; i++) {
                    String chunk = "{\"part\":" + i + "}";
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
