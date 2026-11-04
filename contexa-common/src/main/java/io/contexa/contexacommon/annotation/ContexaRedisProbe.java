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
package io.contexa.contexacommon.annotation;

import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.time.Duration;

/**
 * Asks the Redis of the distributed mode whether it answers, before anything of Contexa is created: Contexa's beans subscribe
 * to it at start. A Redis that is still coming up is waited for within a short window. Only a single server can be asked: the
 * nodes of a cluster or a sentinel are left to their client, which has its own view of which of them count.
 */
class ContexaRedisProbe {

    private static final Duration DEFAULT_WINDOW = Duration.ofSeconds(5);
    private static final Duration DEFAULT_PAUSE = Duration.ofSeconds(1);
    private static final int CONNECT_TIMEOUT_MILLIS = 1000;
    private static final int DEFAULT_PORT = 6379;

    private final Duration window;
    private final Duration pause;

    ContexaRedisProbe() {
        this(DEFAULT_WINDOW, DEFAULT_PAUSE);
    }

    ContexaRedisProbe(Duration window, Duration pause) {
        this.window = window;
        this.pause = pause;
    }

    /** Why Redis cannot be used, or null when it answers, when the mode has no use for it, or when there is nothing to ask. */
    @Nullable
    String problem(Environment environment) {
        InetSocketAddress address;
        try {
            if (!"distributed".equalsIgnoreCase(environment.getProperty("contexa.infrastructure.mode"))) {
                return null;
            }
            address = singleServer(environment);
        } catch (IllegalArgumentException unresolvedOrUnreadable) {
            return null;
        }
        if (address == null) {
            return null;
        }
        long deadline = System.nanoTime() + window.toNanos();
        String problem;
        do {
            problem = attempt(address);
            if (problem == null) {
                return null;
            }
            if (!pause()) {
                break;
            }
        } while (System.nanoTime() < deadline);
        return problem;
    }

    @Nullable
    private static InetSocketAddress singleServer(Environment environment) {
        if (StringUtils.hasText(environment.getProperty("spring.data.redis.cluster.nodes"))
                || StringUtils.hasText(environment.getProperty("spring.data.redis.cluster.nodes[0]"))
                || StringUtils.hasText(environment.getProperty("spring.data.redis.sentinel.nodes"))
                || StringUtils.hasText(environment.getProperty("spring.data.redis.sentinel.nodes[0]"))) {
            return null;
        }
        String url = environment.getProperty("spring.data.redis.url");
        if (StringUtils.hasText(url)) {
            URI uri = URI.create(url);
            return InetSocketAddress.createUnresolved(uri.getHost(), uri.getPort() > 0 ? uri.getPort() : DEFAULT_PORT);
        }
        String host = environment.getProperty("spring.data.redis.host", "localhost");
        return InetSocketAddress.createUnresolved(host, environment.getProperty("spring.data.redis.port", Integer.class, DEFAULT_PORT));
    }

    @Nullable
    private static String attempt(InetSocketAddress address) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address.getHostString(), address.getPort()), CONNECT_TIMEOUT_MILLIS);
            return null;
        } catch (IOException refused) {
            return address.getHostString() + ":" + address.getPort() + " " + refused.getMessage();
        }
    }

    private boolean pause() {
        try {
            Thread.sleep(pause.toMillis());
            return true;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
