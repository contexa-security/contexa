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
package io.contexa.contexacore.autonomous.saas.client;

import com.sun.net.httpserver.HttpServer;
import io.contexa.contexacore.infra.ContexaReactorResources;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SingleThreadEventLoop;
import io.netty.util.concurrent.EventExecutor;
import org.junit.jupiter.api.Test;
import reactor.netty.http.HttpResources;
import reactor.netty.resources.LoopResources;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A SaaS endpoint that accepts the connection and never answers ends the call after the read timeout, not never. */
class SaasRestClientsTest {

    @Test
    void aServerThatNeverAnswersDoesNotHoldTheCallerForEver() throws Exception {
        try (ServerSocket silent = new ServerSocket(0)) {
            var client = SaasRestClients.create("http://127.0.0.1:" + silent.getLocalPort(), Duration.ofSeconds(2), Duration.ofMillis(500));
            long started = System.nanoTime();

            assertThatThrownBy(() -> client.get().uri("/anything").retrieve().body(String.class)).isInstanceOf(Exception.class);

            assertThat(Duration.ofNanos(System.nanoTime() - started)).as("the call ended by itself").isLessThan(Duration.ofSeconds(10));
        }
    }

    /** The client connects on Contexa's event loop: the connection it keeps is there, and none was added to the JVM's. */
    @Test
    void theClientConnectsOnContexasEventLoopAndNotOnTheJvms() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/answer", exchange -> {
            byte[] body = "answered".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        try {
            int onTheJvmsLoop = channels(HttpResources.get());
            int onContexasLoop = channels(ContexaReactorResources.eventLoops());
            var client = SaasRestClients.create("http://localhost:" + server.getAddress().getPort());

            assertThat(client.get().uri("/answer").retrieve().body(String.class)).isEqualTo("answered");

            assertThat(channels(ContexaReactorResources.eventLoops())).isGreaterThan(onContexasLoop);
            assertThat(channels(HttpResources.get())).isEqualTo(onTheJvmsLoop);
        } finally {
            server.stop(0);
        }
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

    @Test
    void theDefaultsAreShortEnoughForAScheduledSend() {
        assertThat(SaasRestClients.CONNECT_TIMEOUT).isLessThanOrEqualTo(Duration.ofSeconds(10));
        assertThat(SaasRestClients.READ_TIMEOUT).isLessThanOrEqualTo(Duration.ofSeconds(60));
    }
}
