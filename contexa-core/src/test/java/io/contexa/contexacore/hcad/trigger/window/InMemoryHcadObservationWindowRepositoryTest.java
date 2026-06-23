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
package io.contexa.contexacore.hcad.trigger.window;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryHcadObservationWindowRepositoryTest {

    @Test
    @DisplayName("same actor session requests should be coalesced into one observation window")
    void observe_sameActorSession_shouldCoalesce() {
        InMemoryHcadObservationWindowRepository repository = new InMemoryHcadObservationWindowRepository();

        HcadObservationWindowLease first = repository.observe(
                "actor-1",
                observation("r1", "GET", "/api/dashboard"),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));
        HcadObservationWindowLease second = repository.observe(
                "actor-1",
                observation("r2", "GET", "/api/menus"),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));

        assertThat(first.deepEvaluationOwner()).isTrue();
        assertThat(second.deepEvaluationOwner()).isFalse();
        assertThat(second.windowId()).isEqualTo(first.windowId());
        assertThat(second.requestCount()).isEqualTo(2);
        assertThat(second.duplicateSuppressedCount()).isEqualTo(1);
        assertThat(second.samplePaths()).containsExactly("/api/dashboard", "/api/menus");
    }

    @Test
    @DisplayName("different actor sessions should acquire independent windows")
    void observe_differentActorSessions_shouldAcquireIndependently() {
        InMemoryHcadObservationWindowRepository repository = new InMemoryHcadObservationWindowRepository();

        HcadObservationWindowLease first = repository.observe(
                "actor-1",
                observation("r1", "GET", "/api/dashboard"),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));
        HcadObservationWindowLease second = repository.observe(
                "actor-2",
                observation("r2", "GET", "/api/dashboard"),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));

        assertThat(first.deepEvaluationOwner()).isTrue();
        assertThat(second.deepEvaluationOwner()).isTrue();
        assertThat(second.windowId()).isNotEqualTo(first.windowId());
    }

    @Test
    @DisplayName("ten parallel requests in same actor session should produce one deep evaluation owner")
    void observe_tenParallelSameActorRequests_shouldHaveOneOwner() throws Exception {
        InMemoryHcadObservationWindowRepository repository = new InMemoryHcadObservationWindowRepository();
        int requestCount = 10;
        CountDownLatch ready = new CountDownLatch(requestCount);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(requestCount);
        List<Future<HcadObservationWindowLease>> futures = new ArrayList<>();

        for (int i = 0; i < requestCount; i++) {
            int index = i;
            futures.add(executor.submit(() -> {
                ready.countDown();
                start.await(2, TimeUnit.SECONDS);
                return repository.observe(
                        "actor-1",
                        observation("r" + index, "GET", "/api/fanout/" + index),
                        Duration.ofSeconds(1),
                        Duration.ofSeconds(60));
            }));
        }

        assertThat(ready.await(2, TimeUnit.SECONDS)).isTrue();
        start.countDown();
        List<HcadObservationWindowLease> leases = new ArrayList<>();
        for (Future<HcadObservationWindowLease> future : futures) {
            leases.add(future.get(5, TimeUnit.SECONDS));
        }
        executor.shutdownNow();

        assertThat(leases).filteredOn(HcadObservationWindowLease::deepEvaluationOwner).hasSize(1);
        assertThat(leases).extracting(HcadObservationWindowLease::windowId).containsOnly(leases.get(0).windowId());
        HcadObservationWindowLease latest = leases.stream()
                .max((left, right) -> Integer.compare(left.requestCount(), right.requestCount()))
                .orElseThrow();
        assertThat(latest.requestCount()).isEqualTo(requestCount);
        assertThat(latest.duplicateSuppressedCount()).isEqualTo(requestCount - 1);
        assertThat(latest.samplePaths()).hasSize(requestCount);
    }

    @Test
    @DisplayName("same actor session should acquire a new window after coalesce TTL expires")
    void observe_sameActorAfterWindowTtl_shouldAcquireNewWindow() throws Exception {
        InMemoryHcadObservationWindowRepository repository = new InMemoryHcadObservationWindowRepository();

        HcadObservationWindowLease first = repository.observe(
                "actor-1",
                observation("r1", "GET", "/api/dashboard"),
                Duration.ofMillis(25),
                Duration.ofSeconds(60));
        HcadObservationWindowLease second = repository.observe(
                "actor-1",
                observation("r2", "GET", "/api/dashboard"),
                Duration.ofMillis(25),
                Duration.ofSeconds(60));
        Thread.sleep(50L);
        HcadObservationWindowLease third = repository.observe(
                "actor-1",
                observation("r3", "GET", "/api/dashboard"),
                Duration.ofMillis(25),
                Duration.ofSeconds(60));

        assertThat(first.deepEvaluationOwner()).isTrue();
        assertThat(second.deepEvaluationOwner()).isFalse();
        assertThat(second.windowId()).isEqualTo(first.windowId());
        assertThat(third.deepEvaluationOwner()).isTrue();
        assertThat(third.windowId()).isNotEqualTo(first.windowId());
    }

    @Test
    @DisplayName("same window should allow escalation only for a new trusted anchor after deep evaluation")
    void tryAcquireEscalation_sameWindow_shouldRequireCompletedAndNewAnchor() {
        InMemoryHcadObservationWindowRepository repository = new InMemoryHcadObservationWindowRepository();
        HcadObservationWindowLease lease = repository.observe(
                "actor-1",
                observation("r1", "GET", "/api/dashboard"),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));

        assertThat(repository.tryAcquireEscalation(
                "actor-1",
                lease.windowId(),
                "IMPOSSIBLE_TRAVEL")).isFalse();

        repository.markDeepEvaluationCompleted("actor-1", lease.windowId(), "IMPOSSIBLE_TRAVEL");

        assertThat(repository.tryAcquireEscalation(
                "actor-1",
                lease.windowId(),
                "IMPOSSIBLE_TRAVEL")).isFalse();
        assertThat(repository.tryAcquireEscalation(
                "actor-1",
                lease.windowId(),
                "FAILED_LOGIN_BURST")).isTrue();
        assertThat(repository.tryAcquireEscalation(
                "actor-1",
                lease.windowId(),
                "FAILED_LOGIN_BURST")).isFalse();
    }

    private HcadRequestObservation observation(String requestId, String method, String path) {
        return new HcadRequestObservation(requestId, method, path, path, Instant.now());
    }
}
