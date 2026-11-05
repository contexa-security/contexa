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
package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.store.ContexaStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestPathDatabaseGuardTest {

    private static final Duration WAIT = Duration.ofMillis(150);

    private final RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(WAIT, 2);
    private final CountDownLatch databaseBack = new CountDownLatch(1);

    @AfterEach
    void release() {
        databaseBack.countDown();
        guard.destroy();
    }

    private String hanging() {
        try {
            databaseBack.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return "late";
    }

    private static long millisOf(Runnable call) {
        long started = System.nanoTime();
        call.run();
        return Duration.ofNanos(System.nanoTime() - started).toMillis();
    }

    /** Q-7: one request pays for the outage; while the gate is down nothing reaches the database. */
    @Test
    void aWaitThatEndsLowersTheGateAndTheNextRequestDoesNotWait() {
        ContexaStores stores = new ContexaStores();
        stores.database().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        RequestPathDatabaseGuard gated = new RequestPathDatabaseGuard(WAIT, 2, stores.database());
        try {
            assertThat(gated.call(this::hanging, "unavailable")).isEqualTo("unavailable");
            assertThat(stores.database().isDown()).isTrue();

            AtomicBoolean worked = new AtomicBoolean();
            long millis = millisOf(() -> assertThat(gated.call(() -> {
                worked.set(true);
                return "answer";
            }, "unavailable")).isEqualTo("unavailable"));

            assertThat(worked).isFalse();
            assertThat(millis).isLessThan(WAIT.toMillis());
        } finally {
            gated.destroy();
            stores.destroy();
        }
    }

    @Test
    void aDatabaseThatAnswersGivesTheRequestItsAnswer() {
        assertThat(guard.call(() -> "answer", "unavailable")).isEqualTo("answer");
    }

    @Test
    void aDatabaseThatDoesNotAnswerCostsTheRequestTheWaitAndNoMore() {
        AtomicReference<String> answer = new AtomicReference<>();

        long millis = millisOf(() -> answer.set(guard.call(this::hanging, "unavailable")));

        assertThat(answer.get()).isEqualTo("unavailable");
        assertThat(millis).isGreaterThanOrEqualTo(WAIT.toMillis() - 20).isLessThan(WAIT.toMillis() + 1000);
    }

    @Test
    void whenEveryWorkerIsHeldTheNextRequestDoesNotWaitAtAll() {
        guard.call(this::hanging, "unavailable");
        guard.call(this::hanging, "unavailable");
        AtomicReference<String> answer = new AtomicReference<>();

        long millis = millisOf(() -> answer.set(guard.call(this::hanging, "unavailable")));

        assertThat(answer.get()).isEqualTo("unavailable");
        assertThat(millis).isLessThan(WAIT.toMillis());
    }

    @Test
    void aFailureOfTheWorkIsTheCallersToHandleAsBefore() {
        assertThatThrownBy(() -> guard.call(() -> {
            throw new IllegalArgumentException("no such table");
        }, "unavailable")).isInstanceOf(IllegalArgumentException.class).hasMessage("no such table");
    }

    @Test
    void whenTheDatabaseIsBackTheRequestsGetAnswersAgain() throws Exception {
        guard.call(this::hanging, "unavailable");
        guard.call(this::hanging, "unavailable");
        assertThat(guard.call(() -> "answer", "unavailable")).isEqualTo("unavailable");

        databaseBack.countDown();
        Thread.sleep(100);

        assertThat(guard.call(() -> "answer", "unavailable")).isEqualTo("answer");
    }

    @Test
    void aWorkerNeverKeepsTheJvmAlive() {
        AtomicBoolean daemon = new AtomicBoolean();
        AtomicReference<String> name = new AtomicReference<>();

        guard.call(() -> {
            daemon.set(Thread.currentThread().isDaemon());
            name.set(Thread.currentThread().getName());
            return "answer";
        }, "unavailable");

        assertThat(daemon).isTrue();
        assertThat(name.get()).startsWith("contexa-request-database-");
    }

    @Test
    void anInterruptedRequestGoesOnAndKeepsItsInterrupt() {
        Thread.currentThread().interrupt();
        try {
            assertThat(guard.call(this::hanging, "unavailable")).isEqualTo("unavailable");
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void afterTheContextIsClosedARequestStillGoesOn() {
        guard.destroy();

        assertThat(guard.call(() -> "answer", "unavailable")).isEqualTo("unavailable");
    }
}
