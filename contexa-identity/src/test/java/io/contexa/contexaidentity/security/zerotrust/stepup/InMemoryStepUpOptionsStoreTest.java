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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryStepUpOptionsStoreTest {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-03T10:00:00Z"));
    private final Clock clock = new Clock() {
        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    };
    private final InMemoryStepUpOptionsStore store = new InMemoryStepUpOptionsStore(clock);

    @Test
    @DisplayName("a claim goes to the first caller and is held for the time given")
    void aClaimIsHeld() {
        assertThat(store.claim("k", Duration.ofSeconds(30))).isTrue();
        assertThat(store.claim("k", Duration.ofSeconds(30))).isFalse();

        now.set(now.get().plusSeconds(29));
        assertThat(store.claim("k", Duration.ofSeconds(30))).as("still held").isFalse();
        now.set(now.get().plusSeconds(2));
        assertThat(store.claim("k", Duration.ofSeconds(30))).as("held no longer").isTrue();
    }

    @Test
    @DisplayName("a released claim can be taken again at once; claims of other keys are apart")
    void aReleasedClaimIsFree() {
        assertThat(store.claim("a", Duration.ofMinutes(5))).isTrue();
        assertThat(store.claim("b", Duration.ofMinutes(5))).isTrue();

        store.release("a");

        assertThat(store.claim("a", Duration.ofMinutes(5))).isTrue();
        assertThat(store.claim("b", Duration.ofMinutes(5))).isFalse();
    }

    @Test
    @DisplayName("sixteen callers at once: exactly one gets the claim")
    void oneWinnerAmongMany() throws Exception {
        AtomicInteger winners = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        Thread[] threads = new Thread[16];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                if (store.claim("race", Duration.ofMinutes(10))) {
                    winners.incrementAndGet();
                }
            });
            threads[i].start();
        }
        start.countDown();
        for (Thread thread : threads) {
            thread.join();
        }

        assertThat(winners.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("a claim does not touch the options kept under other keys")
    void aClaimLeavesOptionsAlone() {
        store.put("options", "kept");

        store.claim("other", Duration.ofMinutes(1));

        assertThat(store.take("options", String.class)).isEqualTo("kept");
    }

    /** Claims are made for every address asked for, by anyone, and nothing else may ever empty them. */
    @Test
    @DisplayName("the sweep frees what has expired, claims too, and keeps what stands")
    void theSweepFreesWhatExpired() {
        store.claim("expired", Duration.ofSeconds(10));
        store.claim("held", Duration.ofMinutes(10));
        store.put("options", "kept");
        now.set(now.get().plusSeconds(11));

        store.removeExpiredEntries();

        assertThat((Map<?, ?>) ReflectionTestUtils.getField(store, "entries")).hasSize(2);
        assertThat(store.claim("held", Duration.ofMinutes(10))).as("held still").isFalse();
        assertThat(store.take("options", String.class)).isEqualTo("kept");
    }
}
