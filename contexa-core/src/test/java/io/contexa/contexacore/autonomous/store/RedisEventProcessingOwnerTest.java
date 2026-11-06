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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.store.SecurityContextDataStore.EventProcessingClaim;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore.EventProcessingLease;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Who may take an event whose analysis another process started: nobody while that process lives, and whoever gets the
 * event next once it is gone, however it came back. A container comes back as PID 1 again, under the same host name or a
 * new one; two live containers can look the same from here.
 */
@EnabledIf("io.contexa.contexacore.autonomous.store.RedisEventProcessingOwnerTest#isRedisAvailable")
class RedisEventProcessingOwnerTest {

    private static final String HOST =
            System.getProperty("contexa.test.redis.host", System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port", System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));
    private static final String EVENT = "event-of-a-process";

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;

    private final List<RedisSecurityContextDataStore> stores = new ArrayList<>();

    static boolean isRedisAvailable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 500);
            return true;
        } catch (Exception unreachable) {
            return false;
        }
    }

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(HOST, PORT));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void flush() {
        redis.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
    }

    @AfterEach
    void closeStores() {
        stores.forEach(RedisSecurityContextDataStore::close);
    }

    /** A process of its own: every store says it lives under its own name. */
    private RedisSecurityContextDataStore process() {
        RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redis);
        stores.add(store);
        return store;
    }

    private static void claimHeldBy(String ownerToken) {
        redis.opsForValue().set(ZeroTrustRedisKeys.eventProcessing(EVENT), ownerToken, Duration.ofMinutes(30));
    }

    private static void saysItLives(String instance, Duration forHowLong) {
        redis.opsForValue().set(ZeroTrustRedisKeys.processAlive(instance), "1", forHowLong);
    }

    @Test
    void aLiveProcessKeepsWhatItAnalyses() {
        RedisSecurityContextDataStore first = process();
        EventProcessingLease lease = first.claimEventProcessingLease(EVENT);

        assertThat(process().claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
        assertThat(first.isEventProcessingOwner(EVENT, lease.ownerToken())).isTrue();
    }

    @Test
    void itsOwnClaimIsInFlightToTheProcessItself() {
        RedisSecurityContextDataStore first = process();
        first.claimEventProcessingLease(EVENT);

        assertThat(first.claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    /** A sign of life lost to a Redis that lost its keys: the process still holds what it analyses. */
    @Test
    void itsOwnClaimStaysItsOwnWhenItsSignOfLifeIsMissing() {
        RedisSecurityContextDataStore first = process();
        String[] parts = first.claimEventProcessingLease(EVENT).ownerToken().split(":");
        redis.delete(ZeroTrustRedisKeys.processAlive(parts[2]));

        assertThat(first.claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    /** Same host name, same PID: {@code docker restart} of a container. Both stores here are that. */
    @Test
    void theProcessThatCameBackAsTheSamePidOnTheSameHostTakesTheEvent() {
        RedisSecurityContextDataStore died = process();
        EventProcessingLease lease = died.claimEventProcessingLease(EVENT);
        died.close();

        RedisSecurityContextDataStore next = process();
        EventProcessingLease taken = next.claimEventProcessingLease(EVENT);

        assertThat(taken.claim()).isEqualTo(EventProcessingClaim.ACQUIRED);
        assertThat(next.isEventProcessingOwner(EVENT, lease.ownerToken())).isFalse();
    }

    /** A new container: PID 1 under a host name of its own. */
    @Test
    void theProcessOnANewHostTakesTheEventOfOneThatDied() {
        claimHeldBy("pod-before-the-restart:1:instance-that-died:nonce");

        assertThat(process().claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.ACQUIRED);
    }

    @Test
    void aLiveProcessOnAnotherHostKeepsItsClaimWhateverItsPid() {
        saysItLives("instance-on-another-host", Duration.ofMinutes(1));
        claimHeldBy("another-host:1:instance-on-another-host:nonce");

        assertThat(process().claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    /** Two containers named alike, each its own PID 1: the host name and the PID tell nothing, the instance does. */
    @Test
    void aLiveProcessThatLooksLikeThisOneKeepsItsClaim() {
        RedisSecurityContextDataStore here = process();
        String token = here.claimEventProcessingLease("event-for-the-name").ownerToken();
        String[] parts = token.split(":");
        saysItLives("instance-of-the-twin", Duration.ofMinutes(1));
        claimHeldBy(parts[0] + ":" + parts[1] + ":instance-of-the-twin:nonce");

        assertThat(here.claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    @Test
    void aProcessKilledIsSeenGoneOnceWhatItLastSaidRunsOut() {
        saysItLives("instance-killed", Duration.ofMillis(400));
        claimHeldBy("host:1:instance-killed:nonce");
        RedisSecurityContextDataStore next = process();

        assertThat(next.claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);

        Awaitility.await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(50))
                .until(() -> next.claimEventProcessingLease(EVENT).claim() == EventProcessingClaim.ACQUIRED);
    }

    @Test
    void aLiveProcessKeepsSayingSoLongAfterWhatItFirstSaidWouldHaveRunOut() throws Exception {
        RedisSecurityContextDataStore alive = process();
        alive.setAliveBeat(Duration.ofMillis(100));
        alive.claimEventProcessingLease(EVENT);
        RedisSecurityContextDataStore other = process();

        Thread.sleep(1_000);

        assertThat(other.claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    @Test
    void whatTheDeadOneFinishedStaysFinished() {
        RedisSecurityContextDataStore died = process();
        EventProcessingLease lease = died.claimEventProcessingLease(EVENT);
        died.markEventProcessed(EVENT, lease.ownerToken());
        died.close();

        assertThat(process().claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.PROCESSED);
    }

    @Test
    void onlyOneOfTheProcessesAfterADeadOneTakesTheEvent() throws Exception {
        claimHeldBy("pod-before-the-restart:1:instance-that-died:nonce");
        List<RedisSecurityContextDataStore> next = List.of(process(), process(), process(), process());
        ExecutorService threads = Executors.newFixedThreadPool(next.size());
        List<Callable<EventProcessingClaim>> claims = new ArrayList<>();
        next.forEach(store -> claims.add(() -> store.claimEventProcessingLease(EVENT).claim()));

        List<EventProcessingClaim> results = new ArrayList<>();
        for (Future<EventProcessingClaim> claim : threads.invokeAll(claims)) {
            results.add(claim.get());
        }
        threads.shutdown();

        assertThat(results).containsOnlyOnce(EventProcessingClaim.ACQUIRED);
    }

    /** What the older version wrote stays until its claim ends: nothing here says that process is gone. */
    @Test
    void aClaimThatNamesNoInstanceStaysUntilItEnds() {
        claimHeldBy("old-host:42:0fd1a1d8-6cf6-4bd3-b89f-1b8ed1c2a4a0");

        assertThat(process().claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    /** A store that cannot be read says nothing of the owner: the event is left alone, and the caller goes on. */
    @Test
    @SuppressWarnings("unchecked")
    void aStoreThatCannotBeReadTakesNothingAway() {
        RedisTemplate<String, Object> broken = mock(RedisTemplate.class);
        when(broken.opsForValue()).thenThrow(new IllegalStateException("Redis is away"));
        when(broken.execute(any(RedisCallback.class))).thenThrow(new IllegalStateException("Redis is away"));
        RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(broken);
        stores.add(store);

        assertThat(store.claimEventProcessingLease(EVENT).claim()).isEqualTo(EventProcessingClaim.IN_FLIGHT);
    }

    @Test
    void closingLeavesNoSignOfLife() {
        RedisSecurityContextDataStore process = process();
        String[] parts = process.claimEventProcessingLease(EVENT).ownerToken().split(":");

        assertThat(redis.hasKey(ZeroTrustRedisKeys.processAlive(parts[2]))).isTrue();
        process.close();
        assertThat(redis.hasKey(ZeroTrustRedisKeys.processAlive(parts[2]))).isFalse();
    }

    @Test
    void aSignOfLifeEndsByItself() {
        RedisSecurityContextDataStore process = process();
        String[] parts = process.claimEventProcessingLease(EVENT).ownerToken().split(":");

        Long ttl = redis.getExpire(ZeroTrustRedisKeys.processAlive(parts[2]));

        assertThat(ttl).isPositive().isLessThanOrEqualTo(15L);
    }
}
