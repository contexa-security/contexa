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

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisHcadObservationWindowRepositoryTest {

    @Test
    @DisplayName("Redis observation repository should coalesce same actor session like the in-memory repository")
    @SuppressWarnings({"unchecked", "rawtypes"})
    void observe_sameActorSession_shouldCoalesceAtomically() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        FakeObservationScript fakeScript = new FakeObservationScript();
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object[].class)))
                .thenAnswer(fakeScript::execute);
        RedisHcadObservationWindowRepository repository = new RedisHcadObservationWindowRepository(redisTemplate);

        HcadObservationWindowLease first = repository.observe(
                "actor-1",
                new HcadRequestObservation("req-1", "GET", "/api/a", "/api/a", Instant.now()),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));
        HcadObservationWindowLease second = repository.observe(
                "actor-1",
                new HcadRequestObservation("req-2", "POST", "/api/b/123", "/api/b/{id}", Instant.now()),
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));

        assertThat(first.deepEvaluationOwner()).isTrue();
        assertThat(second.deepEvaluationOwner()).isFalse();
        assertThat(second.windowId()).isEqualTo(first.windowId());
        assertThat(second.requestCount()).isEqualTo(2);
        assertThat(second.duplicateSuppressedCount()).isEqualTo(1);
        assertThat(second.samplePaths()).containsExactly("/api/a", "/api/b/123");
        assertThat(second.resourceFamilies()).containsExactly("/api/a", "/api/b/{id}");
        verify(redisTemplate, times(2)).execute(any(RedisScript.class), anyList(), any(Object[].class));
    }

    @Test
    @DisplayName("Redis observation repository should keep one owner for ten parallel same actor requests")
    @SuppressWarnings({"unchecked", "rawtypes"})
    void observe_tenParallelSameActorRequests_shouldHaveOneOwner() throws Exception {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        FakeObservationScript fakeScript = new FakeObservationScript();
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object[].class)))
                .thenAnswer(fakeScript::execute);
        RedisHcadObservationWindowRepository repository = new RedisHcadObservationWindowRepository(redisTemplate);
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
                        new HcadRequestObservation("req-" + index, "GET", "/api/fanout/" + index,
                                "/api/fanout/{id}", Instant.now()),
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
        assertThat(latest.resourceFamilies()).containsExactly("/api/fanout/{id}");
        verify(redisTemplate, times(requestCount)).execute(any(RedisScript.class), anyList(), any(Object[].class));
    }

    @Test
    @DisplayName("Redis repository should allow same-window escalation only for a new trusted anchor")
    @SuppressWarnings("unchecked")
    void tryAcquireEscalation_sameWindow_shouldRequireCompletedAndNewAnchor() {
        String actorSessionKey = "actor-1";
        String windowId = "window-1";
        String existingAnchor = "IMPOSSIBLE_TRAVEL";
        String newAnchor = "FAILED_LOGIN_BURST";
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ValueOperations<String, String> valueOperations = mock(ValueOperations.class);
        SetOperations<String, String> setOperations = mock(SetOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        String deepEvaluationKey = ZeroTrustRedisKeys.hcadObservationWindowDeepEvaluation(actorSessionKey, windowId);
        String anchorKey = ZeroTrustRedisKeys.hcadObservationWindowAnchorSignatures(actorSessionKey, windowId);
        String observationKey = ZeroTrustRedisKeys.hcadObservationWindowObservations(actorSessionKey, windowId);
        when(redisTemplate.hasKey(deepEvaluationKey)).thenReturn(false, true, true);
        when(redisTemplate.getExpire(observationKey)).thenReturn(30L);
        when(setOperations.add(anchorKey, existingAnchor)).thenReturn(1L, 0L);
        when(setOperations.add(anchorKey, newAnchor)).thenReturn(1L, 0L);
        RedisHcadObservationWindowRepository repository = new RedisHcadObservationWindowRepository(redisTemplate);

        assertThat(repository.tryAcquireEscalation(actorSessionKey, windowId, existingAnchor)).isFalse();

        repository.markDeepEvaluationCompleted(actorSessionKey, windowId, existingAnchor);

        assertThat(repository.tryAcquireEscalation(actorSessionKey, windowId, existingAnchor)).isFalse();
        assertThat(repository.tryAcquireEscalation(actorSessionKey, windowId, newAnchor)).isTrue();
        assertThat(repository.tryAcquireEscalation(actorSessionKey, windowId, newAnchor)).isFalse();
        verify(valueOperations).set(deepEvaluationKey, "1", Duration.ofSeconds(30));
        verify(setOperations, times(4)).add(anyString(), anyString());
    }

    @Test
    @DisplayName("Redis repository should suppress actor-session evaluation by trusted context signature")
    @SuppressWarnings("unchecked")
    void tryAcquireActorSessionEvaluation_sameSignatureWithinTtl_shouldUseSetIfAbsent() {
        String actorSessionKey = "actor-1";
        String signature = "NO_TRUSTED_ANCHOR_SIGNAL";
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ValueOperations<String, String> valueOperations = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.setIfAbsent(
                ZeroTrustRedisKeys.hcadActorSessionEvaluation(actorSessionKey, signature),
                "1",
                Duration.ofSeconds(30))).thenReturn(true, false);
        RedisHcadObservationWindowRepository repository = new RedisHcadObservationWindowRepository(redisTemplate);

        assertThat(repository.tryAcquireActorSessionEvaluation(
                actorSessionKey,
                signature,
                Duration.ofSeconds(30))).isTrue();
        assertThat(repository.tryAcquireActorSessionEvaluation(
                actorSessionKey,
                signature,
                Duration.ofSeconds(30))).isFalse();
        assertThat(repository.tryAcquireActorSessionEvaluation(
                actorSessionKey,
                "REQUEST_BURST_BUCKET:2",
                Duration.ofSeconds(30))).isFalse();
    }

    private static final class FakeObservationScript {
        private final Map<String, String> windows = new HashMap<>();
        private final Map<String, List<String>> observations = new HashMap<>();

        private synchronized List<String> execute(InvocationOnMock invocation) {
            List<String> keys = invocation.getArgument(1);
            Object[] argv = argv(invocation);
            String windowKey = keys.get(0);
            String newWindowId = value(argv, 0);
            String observationPrefix = value(argv, 2);
            String encodedObservation = value(argv, 3);

            String windowId = windows.get(windowKey);
            boolean acquired = false;
            if (windowId == null || windowId.isBlank()) {
                windowId = newWindowId;
                windows.put(windowKey, windowId);
                acquired = true;
            }
            String observationKey = observationPrefix + windowId;
            if (encodedObservation != null && !encodedObservation.isBlank()) {
                observations.computeIfAbsent(observationKey, ignored -> new ArrayList<>()).add(encodedObservation);
            }
            List<String> values = observations.getOrDefault(observationKey, List.of());
            List<String> result = new ArrayList<>();
            result.add(acquired ? "1" : "0");
            result.add(windowId);
            result.add(Integer.toString(values.size()));
            result.addAll(values);
            return result;
        }

        private Object[] argv(InvocationOnMock invocation) {
            Object[] arguments = invocation.getArguments();
            if (arguments.length == 3 && arguments[2] instanceof Object[] varargs) {
                return varargs;
            }
            return Arrays.copyOfRange(arguments, 2, arguments.length);
        }

        private String value(Object[] argv, int index) {
            if (argv == null || argv.length <= index || argv[index] == null) {
                return null;
            }
            return argv[index].toString();
        }
    }
}
