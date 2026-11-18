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
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.http.MediaType;
import org.springframework.http.client.ReactorClientHttpRequestFactory;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.Callable;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K129: a model call the provider call limit cuts closes its connection, so the model server stops the answer nobody
 * waits for and the next call does not run beside it. The call is the one a model client makes on the Reactor Netty
 * request factory Contexa gives its model calls; the server reads the request, answers nothing and reads on until the
 * client closes. The limit leaves the client the time to send the request first.
 */
class ProviderCallCutClosesConnectionTest {

    @Test
    void aCallCutByTheProviderCallLimitClosesItsConnection() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getLlmTimeout().setProviderCallTimeoutMs(1_000L);
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(null, null, new TieredLLMProperties(),
                new AdvisorRegistry(), properties);
        ExecutionContext context = ExecutionContext.from(new Prompt("name these resources"));
        RestClient client = RestClient.builder().requestFactory(new ReactorClientHttpRequestFactory()).build();
        // A first call to a server that answers starts the client, so that the cut call is sent at once.
        try (ServerSocket answering = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread answer = new Thread(() -> {
                try (Socket accepted = answering.accept()) {
                    InputStream request = accepted.getInputStream();
                    String head = readHead(request);
                    request.readNBytes(contentLength(head));
                    accepted.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + "Content-Length: 2\r\nConnection: close\r\n\r\n{}").getBytes(StandardCharsets.US_ASCII));
                } catch (Exception ignored) {
                    // the warm-up call fails the test below if it fails
                }
            });
            answer.start();
            assertThat(call(client, answering.getLocalPort())).isEqualTo("{}");
            answer.join(5_000L);
        }
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread caller = new Thread(() -> {
                try {
                    ReflectionTestUtils.invokeMethod(orchestrator, "executeProviderCallWithinTimeout", context, null,
                            (Callable<String>) () -> call(client, silent.getLocalPort()));
                } catch (RuntimeException expected) {
                    context.addMetadata("cutBy", expected.getClass().getSimpleName());
                }
            });
            caller.start();

            try (Socket accepted = silent.accept()) {
                accepted.setSoTimeout(15_000);
                InputStream request = accepted.getInputStream();
                String head = readHead(request);
                long started = System.nanoTime();
                boolean closed;
                try {
                    while (request.read() != -1) {
                        // the body, then the end of the stream once the client closes the connection
                    }
                    closed = true;
                } catch (SocketTimeoutException stillOpen) {
                    closed = false;
                }
                long waitedMs = (System.nanoTime() - started) / 1_000_000L;

                assertThat(head).startsWith("POST /api/chat");
                assertThat(closed).as("the cut call closed its connection (waited %d ms)", waitedMs).isTrue();
                assertThat(waitedMs).isLessThan(8_000L);
            }
            caller.join(10_000L);
            assertThat(context.getMetadata()).containsEntry("cutBy", "ProviderCallTimeoutException");
        }
    }

    private static String call(RestClient client, int port) {
        return client.post().uri("http://127.0.0.1:" + port + "/api/chat").contentType(MediaType.APPLICATION_JSON)
                .body("{\"model\":\"qwen3:8b\",\"stream\":false}").retrieve().body(String.class);
    }

    /** The length of the body the request head announces. */
    private static int contentLength(String head) {
        for (String line : head.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                return Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }
        return 0;
    }

    /** The request line and headers, up to the empty line that ends them. */
    private static String readHead(InputStream input) throws IOException {
        StringBuilder head = new StringBuilder();
        int read;
        while ((read = input.read()) != -1) {
            head.append((char) read);
            if (head.length() >= 4 && head.substring(head.length() - 4).equals("\r\n\r\n")) {
                break;
            }
        }
        return head.toString();
    }
}
