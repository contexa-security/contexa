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
package io.contexa.contexacommon.store;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.QueryTimeoutException;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@ExtendWith(OutputCaptureExtension.class)
class StoreGateTest {

    private final AtomicInteger back = new AtomicInteger();
    private final StoreGate gate = new StoreGate("Redis", back::incrementAndGet, Duration.ofMillis(20));

    @AfterEach
    void stop() {
        gate.stop();
    }

    @Test
    @DisplayName("a failure of the store lowers the gate; a look that finds it answering raises it")
    void aFailureLowersAndALookRaises() {
        AtomicBoolean answering = new AtomicBoolean();
        gate.watchWith(() -> {
            if (!answering.get()) {
                throw new IllegalStateException("still down");
            }
        });

        gate.fail(new QueryTimeoutException("Redis command timed out"));
        assertThat(gate.isDown()).isTrue();

        answering.set(true);
        await().atMost(Duration.ofSeconds(5)).until(() -> !gate.isDown());
        assertThat(back).hasValue(1);
    }

    @Test
    @DisplayName("the store goes down and comes back again as often as it does")
    void itGoesDownAgain() {
        gate.watchWith(() -> {
        });
        gate.fail(new QueryTimeoutException("first"));
        await().atMost(Duration.ofSeconds(5)).until(() -> !gate.isDown());

        gate.fail(new QueryTimeoutException("second"));
        await().atMost(Duration.ofSeconds(5)).until(() -> !gate.isDown());

        assertThat(back).hasValue(2);
    }

    @Test
    @DisplayName("a failure that is not the store's leaves the gate up")
    void anotherFailureLeavesTheGateUp() {
        gate.watchWith(() -> {
        });

        gate.fail(new IllegalArgumentException("a wrong script"));

        assertThat(gate.isDown()).isFalse();
    }

    @Test
    @DisplayName("without a way to look for the store the gate stays up: nothing could raise it")
    void withoutAProbeTheGateStaysUp() {
        gate.fail(new QueryTimeoutException("Redis command timed out"));

        assertThat(gate.isDown()).isFalse();
    }

    @Test
    @DisplayName("an outage is reported once, however many requests meet it")
    void anOutageIsReportedOnce(CapturedOutput output) {
        gate.watchWith(() -> {
            throw new IllegalStateException("still down");
        });

        for (int request = 0; request < 50; request++) {
            gate.fail(new QueryTimeoutException("Redis command timed out"));
        }

        assertThat(output).containsOnlyOnce("Redis does not answer");
    }

    @Test
    @DisplayName("the outage is reported with what made it, and its end with how long it took")
    void theOutageIsReportedWithItsCause(CapturedOutput output) {
        gate.watchWith(() -> {
        });

        gate.fail(new QueryTimeoutException("Redis command timed out"));
        await().atMost(Duration.ofSeconds(5)).until(() -> !gate.isDown());

        assertThat(output).contains("QueryTimeoutException: Redis command timed out").contains("Redis answers again");
    }
}
