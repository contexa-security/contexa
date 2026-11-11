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
package io.contexa.contexacore.infra;

import com.sun.net.httpserver.HttpServer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SingleThreadEventLoop;
import io.netty.util.concurrent.EventExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import reactor.core.Scannable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.netty.http.HttpResources;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Contexa's event loop and timer: threads of its own, named as Contexa's, few, that no application's code shares, and that end when
 * the last application context holding them closes. The controls show what a client and a timer given nothing run on: the JVM's
 * {@code reactor-http-nio} and {@code parallel}.
 */
class ContexaReactorResourcesTest {

    private HttpServer server;

    @BeforeEach
    void startAServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newFixedThreadPool(4, task -> {
            Thread thread = new Thread(task, "test-server");
            thread.setDaemon(true);
            return thread;
        }));
        server.createContext("/answer", exchange -> {
            byte[] body = "answered".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/slow", exchange -> {
            try {
                Thread.sleep(1_500L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] body = "late".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    @AfterEach
    void stopTheServer() {
        server.stop(0);
    }

    /** By name, so that the name is looked up as a model server's is. */
    private String url(String path) {
        return "http://localhost:" + server.getAddress().getPort() + path;
    }

    @Test
    void contexasTimerRunsOnDaemonThreadsOfItsOwnThatRefuseToBlockAsReactorsParallelOnesDo() {
        String thread = Mono.delay(Duration.ofMillis(10), ContexaReactorResources.timer())
                .map(tick -> Thread.currentThread().getName() + "|" + Thread.currentThread().isDaemon() + "|"
                        + Schedulers.isInNonBlockingThread())
                .block(Duration.ofSeconds(5));

        assertThat(thread).startsWith("contexa-timer-").endsWith("|true|true");
        // the control: a delay given no scheduler runs on the scheduler the whole JVM shares
        assertThat(Mono.delay(Duration.ofMillis(10)).map(tick -> Thread.currentThread().getName()).block(Duration.ofSeconds(5)))
                .startsWith("parallel-");
    }

    @Test
    void manyTimersAtOnceShareTheFewThreadsOfTheTimer() {
        Set<String> threads = Flux.range(0, 200)
                .flatMap(i -> Mono.delay(Duration.ofMillis(20), ContexaReactorResources.timer())
                        .map(tick -> Thread.currentThread().getName()), 200)
                .collect(Collectors.toSet())
                .block(Duration.ofSeconds(10));

        assertThat(threads).isNotEmpty().hasSizeLessThanOrEqualTo(ContexaReactorResources.TIMER_THREADS)
                .allSatisfy(name -> assertThat(name).startsWith("contexa-timer-"));
    }

    @Test
    void aClientOnContexasLoopConnectsAndLooksTheNameUpThereAndNotOnTheJvmsLoop() {
        List<String> connectedOn = new CopyOnWriteArrayList<>();
        // the control first: a client given nothing connects on the JVM's loop
        assertThat(HttpClient.create().doOnConnected(connection -> connectedOn.add(Thread.currentThread().getName()))
                .get().uri(url("/answer")).responseContent().aggregate().asString().block(Duration.ofSeconds(10))).isEqualTo("answered");
        assertThat(connectedOn).singleElement().satisfies(name -> assertThat(name).startsWith("reactor-http-"));
        int onTheJvmsLoop = channels(HttpResources.get());

        connectedOn.clear();
        HttpClient contexas = ContexaReactorResources.onContexaLoops(HttpClient.create(ConnectionProvider.create("test-contexa", 4)))
                .doOnConnected(connection -> connectedOn.add(Thread.currentThread().getName()));
        assertThat(contexas.get().uri(url("/answer")).responseContent().aggregate().asString().block(Duration.ofSeconds(10)))
                .isEqualTo("answered");

        assertThat(connectedOn).singleElement().satisfies(name -> assertThat(name).startsWith("contexa-ai-"));
        // neither the connection nor the socket of the name lookup is on the JVM's loop
        assertThat(channels(HttpResources.get())).isEqualTo(onTheJvmsLoop);
        assertThat(channels(ContexaReactorResources.eventLoops())).isPositive();
        assertThat(aliveThreads("contexa-ai-")).hasSizeLessThanOrEqualTo(ContexaReactorResources.EVENT_LOOP_THREADS);
    }

    @Test
    void aBuilderOfReactorNettysRequestFactoriesKeepsItsSettingsOnContexasLoopAndAnyOtherIsLeftAsItIs() {
        ClientHttpRequestFactoryBuilder<?> jdk = ClientHttpRequestFactoryBuilder.jdk();
        assertThat(ContexaReactorResources.onContexaLoops(jdk)).isSameAs(jdk);

        List<String> connectedOn = new CopyOnWriteArrayList<>();
        ClientHttpRequestFactoryBuilder<?> reactor = ClientHttpRequestFactoryBuilder.reactor()
                .withHttpClientCustomizer(client -> client.doOnConnected(connection -> connectedOn.add(Thread.currentThread().getName())));
        RestClient client = RestClient.builder().requestFactory(ContexaReactorResources.onContexaLoops(reactor)
                .build(ClientHttpRequestFactorySettings.defaults().withReadTimeout(Duration.ofMillis(300)))).build();

        assertThat(client.get().uri(url("/answer")).retrieve().body(String.class)).isEqualTo("answered");
        assertThat(connectedOn).singleElement().satisfies(name -> assertThat(name).startsWith("contexa-ai-"));
        // the read timeout of the settings still ends a call to a server that does not answer in time
        long started = System.nanoTime();
        assertThatThrownBy(() -> client.get().uri(url("/slow")).retrieve().body(String.class)).isInstanceOf(ResourceAccessException.class);
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isLessThan(1_200L);
    }

    @Test
    void aRequestThatWaitsForAConnectionOfContexasPoolWaitsOnContexasTimer() {
        ConnectionProvider one = ContexaReactorResources.connections("test-one-connection", 1);
        HttpClient client = ContexaReactorResources.onContexaLoops(HttpClient.create(one));
        try {
            Mono<String> slow = client.get().uri(url("/slow")).responseContent().aggregate().asString();
            int before = pendingOnTheTimer();
            var first = slow.subscribe();
            var second = slow.subscribe();
            long until = System.currentTimeMillis() + 1_000L;
            while (pendingOnTheTimer() <= before && System.currentTimeMillis() < until) {
                Thread.onSpinWait();
            }
            // the first holds the connection for the server's second and a half; the timer that waits is the second's
            // the second request waits for the one connection, and the limit of its wait is on Contexa's timer
            assertThat(pendingOnTheTimer()).isGreaterThan(before);
            first.dispose();
            second.dispose();
        } finally {
            one.dispose();
        }
    }

    @Test
    void theThreadsEndWhenTheLastHolderLetsGoAndStartAgainAtTheNextUse() {
        ContexaReactorResources.Hold first = ContexaReactorResources.hold();
        ContexaReactorResources.Hold second = ContexaReactorResources.hold();
        try {
            useBoth();
            assertThat(aliveThreads("contexa-ai-")).isNotEmpty();
            assertThat(aliveThreads("contexa-timer-")).isNotEmpty();

            first.close();
            first.close();
            // one holder is left: closing the first twice let go once
            useBoth();
            assertThat(aliveThreads("contexa-ai-")).isNotEmpty();
        } finally {
            first.close();
            second.close();
        }
        awaitNoThread("contexa-ai-");
        awaitNoThread("contexa-timer-");

        // a later use starts new threads
        useBoth();
        assertThat(aliveThreads("contexa-ai-")).isNotEmpty();
        assertThat(aliveThreads("contexa-timer-")).isNotEmpty();
        ContexaReactorResources.hold().close();
        awaitNoThread("contexa-ai-");
        awaitNoThread("contexa-timer-");
    }

    private void useBoth() {
        assertThat(Mono.delay(Duration.ofMillis(5), ContexaReactorResources.timer()).block(Duration.ofSeconds(5))).isZero();
        assertThat(ContexaReactorResources.onContexaLoops(HttpClient.create(ConnectionProvider.create("test-use", 1)))
                .get().uri(url("/answer")).responseContent().aggregate().asString().block(Duration.ofSeconds(10))).isEqualTo("answered");
    }

    /** The tasks the timer's workers hold; every worker is started and idle first, as a just started one counts as running. */
    private static int pendingOnTheTimer() {
        for (int i = 0; i < 4; i++) {
            Mono.delay(Duration.ofMillis(1), ContexaReactorResources.timer()).block(Duration.ofSeconds(5));
        }
        try {
            Thread.sleep(50L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return Scannable.from(ContexaReactorResources.timer()).inners()
                .mapToInt(worker -> worker.scanOrDefault(Scannable.Attr.BUFFERED, 0)).sum();
    }

    /** The channels on the client event loops of these resources: the connections, and a name lookup's socket. */
    static int channels(LoopResources resources) {
        EventLoopGroup group = resources.onClient(LoopResources.DEFAULT_NATIVE);
        int channels = 0;
        for (EventExecutor executor : group) {
            if (executor instanceof SingleThreadEventLoop loop) {
                channels += loop.registeredChannels();
            }
        }
        return channels;
    }

    static List<String> aliveThreads(String prefix) {
        return Thread.getAllStackTraces().keySet().stream().filter(Thread::isAlive).map(Thread::getName)
                .filter(name -> name.startsWith(prefix)).toList();
    }

    static void awaitNoThread(String prefix) {
        long until = System.currentTimeMillis() + 10_000L;
        while (!aliveThreads(prefix).isEmpty() && System.currentTimeMillis() < until) {
            try {
                Thread.sleep(20L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        assertThat(aliveThreads(prefix)).as("threads %s* after the last holder let go", prefix).isEmpty();
    }
}
