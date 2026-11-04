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

import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
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

    @Test
    void theDefaultsAreShortEnoughForAScheduledSend() {
        assertThat(SaasRestClients.CONNECT_TIMEOUT).isLessThanOrEqualTo(Duration.ofSeconds(10));
        assertThat(SaasRestClients.READ_TIMEOUT).isLessThanOrEqualTo(Duration.ofSeconds(60));
    }
}
