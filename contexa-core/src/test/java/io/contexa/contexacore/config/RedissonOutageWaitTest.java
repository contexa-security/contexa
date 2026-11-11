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
package io.contexa.contexacore.config;

import io.contexa.contexacommon.store.StoreFailures;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.redisson.Redisson;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.data.redis.RedisConnectionDetails;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What a request waits for on Contexa's Redisson client when Redis does not answer: a Redis that refuses the connection and one
 * that takes it and says nothing, on a client that has not connected yet. Each call ends in about a second at most, and what it
 * ends in is taken for an outage of Redis by the gate that keeps requests from waiting.
 */
class RedissonOutageWaitTest {

    /** The wait the specification gives a request, with room for a machine busy with the rest of the test. */
    private static final Duration LIMIT = Duration.ofMillis(2000);

    private final List<RedissonClient> clients = new ArrayList<>();
    private final List<Socket> held = new ArrayList<>();
    private ServerSocket silent;

    @AfterEach
    void close() throws IOException {
        for (RedissonClient client : clients) {
            client.shutdown(0, 1, TimeUnit.SECONDS);
        }
        for (Socket socket : held) {
            socket.close();
        }
        if (silent != null) {
            silent.close();
        }
    }

    @Test
    void aRequestWaitsAboutASecondAtMostToConnectAndForAnAnswerAndTriesOnce() {
        RedisProperties properties = new RedisProperties();

        assertThat(RedissonConfiguration.configFor(null, properties).useSingleServer())
                .extracting("connectTimeout", "timeout", "retryAttempts").containsExactly(1000, 1000, 0);
        assertThat(RedissonConfiguration.configFor(sentinel(), properties).useSentinelServers())
                .extracting("connectTimeout", "timeout", "retryAttempts").containsExactly(1000, 1000, 0);
        assertThat(RedissonConfiguration.configFor(cluster(), properties).useClusterServers())
                .extracting("connectTimeout", "timeout", "retryAttempts").containsExactly(1000, 1000, 0);
    }

    @Test
    void anApplicationThatWaitsLessForRedisIsFollowedAndOneThatWaitsMoreIsNot() {
        RedisProperties quick = new RedisProperties();
        quick.setTimeout(Duration.ofMillis(300));
        RedisProperties slow = new RedisProperties();
        slow.setTimeout(Duration.ofSeconds(60));

        assertThat(RedissonConfiguration.configFor(null, quick).useSingleServer())
                .extracting("connectTimeout", "timeout").containsExactly(300, 300);
        assertThat(RedissonConfiguration.configFor(null, slow).useSingleServer())
                .extracting("connectTimeout", "timeout").containsExactly(1000, 1000);
    }

    @Test
    void aRedisThatRefusesTheConnectionEndsEveryCallAtOnce() throws IOException {
        int port;
        try (ServerSocket closed = new ServerSocket(0)) {
            port = closed.getLocalPort();
        }

        assertEveryCallEndsInTimeAsAnOutage(client(port));
    }

    @Test
    void aRedisThatTakesTheConnectionAndSaysNothingEndsEveryCallInAboutASecond() throws IOException {
        silent = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            try {
                while (!silent.isClosed()) {
                    held.add(silent.accept());
                }
            } catch (IOException closed) {
                // the test ended
            }
        }, "silent-redis");
        acceptor.setDaemon(true);
        acceptor.start();

        assertEveryCallEndsInTimeAsAnOutage(client(silent.getLocalPort()));
    }

    private void assertEveryCallEndsInTimeAsAnOutage(RedissonClient client) {
        RLock lock = client.getLock("outage-wait:" + System.nanoTime());
        for (Call call : List.<Call>of(
                () -> lock.tryLock(750, 30000, TimeUnit.MILLISECONDS),
                lock::isHeldByCurrentThread,
                () -> client.getKeys().delete("outage-wait"),
                () -> client.getKeys().countExists("outage-wait"))) {
            long start = System.nanoTime();
            Throwable failure = failureOf(call);
            Duration took = Duration.ofNanos(System.nanoTime() - start);

            assertThat(took).as("the wait of a call").isLessThan(LIMIT);
            assertThat(StoreFailures.isStoreFailure(failure)).as("an outage of the store: " + failure).isTrue();
        }
    }

    private RedissonClient client(int port) {
        RedisProperties properties = new RedisProperties();
        properties.setHost("127.0.0.1");
        properties.setPort(port);
        RedissonClient client = Redisson.create(RedissonConfiguration.configFor(null, properties));
        clients.add(client);
        return client;
    }

    @FunctionalInterface
    private interface Call {
        Object run() throws Exception;
    }

    private static Throwable failureOf(Call call) {
        Throwable[] failure = new Throwable[1];
        assertThatThrownBy(() -> {
            try {
                call.run();
            } catch (Throwable thrown) {
                failure[0] = thrown;
                throw thrown;
            }
        }).isNotNull();
        return failure[0];
    }

    private static RedisConnectionDetails sentinel() {
        return new RedisConnectionDetails() {
            @Override
            public Sentinel getSentinel() {
                return new Sentinel() {
                    @Override
                    public int getDatabase() {
                        return 0;
                    }

                    @Override
                    public String getMaster() {
                        return "mymaster";
                    }

                    @Override
                    public List<Node> getNodes() {
                        return List.of(new Node("s1.example", 26379));
                    }

                    @Override
                    public String getUsername() {
                        return null;
                    }

                    @Override
                    public String getPassword() {
                        return null;
                    }
                };
            }
        };
    }

    private static RedisConnectionDetails cluster() {
        return new RedisConnectionDetails() {
            @Override
            public Cluster getCluster() {
                return () -> List.of(new Node("c1.example", 7000));
            }
        };
    }
}
