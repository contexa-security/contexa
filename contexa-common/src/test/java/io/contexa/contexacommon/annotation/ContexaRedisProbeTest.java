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

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class ContexaRedisProbeTest {

    private final ContexaRedisProbe probe = new ContexaRedisProbe(Duration.ofMillis(200), Duration.ofMillis(50));

    private static MockEnvironment distributed() {
        return new MockEnvironment().withProperty("contexa.infrastructure.mode", "distributed");
    }

    private static int closedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Test
    void aRedisThatDoesNotAnswerIsNamed() throws IOException {
        int port = closedPort();

        assertThat(probe.problem(distributed().withProperty("spring.data.redis.host", "127.0.0.1")
                .withProperty("spring.data.redis.port", String.valueOf(port)))).contains(String.valueOf(port));
    }

    @Test
    void aRedisThatAnswersChangesNothing() throws IOException {
        try (ServerSocket redis = new ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))) {
            assertThat(probe.problem(distributed().withProperty("spring.data.redis.url",
                    "redis://127.0.0.1:" + redis.getLocalPort()))).isNull();
        }
    }

    /** Most applications run standalone and have no Redis at all. */
    @Test
    void theStandaloneModeAsksNothing() {
        assertThat(probe.problem(new MockEnvironment().withProperty("spring.data.redis.port", "1"))).isNull();
    }

    /** One node of a cluster being down is the client's business, not a reason to run without Contexa. */
    @Test
    void aClusterOrASentinelIsLeftToItsClient() {
        assertThat(probe.problem(distributed().withProperty("spring.data.redis.cluster.nodes", "127.0.0.1:1"))).isNull();
        assertThat(probe.problem(distributed().withProperty("spring.data.redis.sentinel.nodes[0]", "127.0.0.1:1"))).isNull();
    }
}
