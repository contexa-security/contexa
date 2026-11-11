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
package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreGate;
import io.contexa.contexacommon.store.StoreUnavailableException;
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.redisson.Redisson;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * The lock of an MFA flow on a real Redis, with the gate that keeps requests from waiting for a Redis that does not answer:
 * a request thread is refused at once while the gate is down, and a thread that serves no request keeps its path; an outage of
 * Redisson reaches the gate, and a failure that is no outage does not.
 */
class MfaStateMachineServiceImplOutageTest {

    private static final String LOCK_PREFIX = "mfa_lock:session:";
    /** Well under the second a request waits for Redis that does not answer, with room for a cold JVM. */
    private static final Duration AT_ONCE = Duration.ofMillis(700);

    private static RedissonClient redisson;

    private final ContexaStores stores = new ContexaStores();
    private final StoreGate gate = stores.redis();
    private final List<RedissonClient> clients = new ArrayList<>();
    private final List<String> keys = new ArrayList<>();

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + server.host() + ":" + server.port());
        redisson = Redisson.create(config);
    }

    @AfterAll
    static void disconnect() {
        redisson.shutdown(0, 1, TimeUnit.SECONDS);
    }

    @BeforeEach
    void theGateLooksForRedisAndFindsItDown() {
        gate.watchWith(() -> {
            throw new IllegalStateException("Redis does not answer");
        });
    }

    @AfterEach
    void clean() {
        RequestContextHolder.resetRequestAttributes();
        stores.destroy();
        keys.forEach(key -> redisson.getKeys().delete(key));
        clients.forEach(client -> client.shutdown(0, 1, TimeUnit.SECONDS));
    }

    @Test
    void aLockIsTakenAndReleasedWhileTheGateIsUp() throws Exception {
        MfaStateMachineServiceImpl service = service(redisson);
        String session = session();
        onRequestThread();

        assertThat(service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS)).isTrue();
        assertThat(lock(session).isLocked()).isTrue();
        service.releaseLock(session);

        assertThat(lock(session).isLocked()).isFalse();
    }

    @Test
    void aRequestThreadIsRefusedAtOnceWhileTheGateIsDownAndRedisIsNotAsked() {
        MfaStateMachineServiceImpl service = service(redisson);
        String session = session();
        gate.fail(new QueryTimeoutException("Redis does not answer"));
        onRequestThread();

        long start = System.nanoTime();
        assertThatThrownBy(() -> service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS))
                .isInstanceOf(StoreUnavailableException.class);

        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(AT_ONCE);
        assertThat(lock(session).isLocked()).as("the lock was not asked for").isFalse();
        assertThatThrownBy(() -> service.onReleaseStateMachine(session)).isInstanceOf(StoreUnavailableException.class);
        assertThatThrownBy(() -> service.beforeSaveFactorContext(session)).isInstanceOf(StoreUnavailableException.class);
    }

    @Test
    void aThreadThatServesNoRequestKeepsItsPathWhileTheGateIsDown() throws Exception {
        MfaStateMachineServiceImpl service = service(redisson);
        String session = session();
        gate.fail(new QueryTimeoutException("Redis does not answer"));

        assertThat(service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS)).isTrue();
        service.releaseLock(session);

        assertThat(lock(session).isLocked()).isFalse();
    }

    @Test
    void aLockHeldWhenTheGateGoesDownIsNotReleasedByARequestThreadAndEndsWithItsLease() throws Exception {
        MfaStateMachineServiceImpl service = service(redisson);
        String session = session();
        onRequestThread();
        assertThat(service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS)).isTrue();
        gate.fail(new QueryTimeoutException("Redis does not answer"));

        long start = System.nanoTime();
        service.releaseLock(session);

        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(AT_ONCE);
        assertThat(lock(session).isLocked()).as("left to its lease").isTrue();
        assertThat(lock(session).remainTimeToLive()).isPositive().isLessThanOrEqualTo(30_000L);
    }

    @Test
    void anOutageOfRedissonReachesTheGateAndTheNextRequestIsRefusedAtOnce() throws IOException {
        int port;
        try (ServerSocket closed = new ServerSocket(0)) {
            port = closed.getLocalPort();
        }
        Config config = new Config();
        config.setLazyInitialization(true);
        config.useSingleServer().setAddress("redis://127.0.0.1:" + port).setConnectTimeout(1000).setTimeout(1000).setRetryAttempts(0);
        RedissonClient unreachable = Redisson.create(config);
        clients.add(unreachable);
        MfaStateMachineServiceImpl service = service(unreachable);
        String session = session();
        onRequestThread();

        assertThat(gate.isDown()).isFalse();
        assertThatThrownBy(() -> service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS))
                .isNotInstanceOf(StoreUnavailableException.class);
        assertThat(gate.isDown()).as("the failure of Redisson was an outage").isTrue();

        long start = System.nanoTime();
        assertThatThrownBy(() -> service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS))
                .isInstanceOf(StoreUnavailableException.class);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(AT_ONCE);
    }

    @Test
    void aFailureThatIsNoOutageLeavesTheGateUp() {
        MfaStateMachineServiceImpl service = service(redisson);
        String session = session();
        redisson.getBucket(key(session)).set("not a lock");
        onRequestThread();

        assertThatThrownBy(() -> service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS)).isInstanceOf(RuntimeException.class);

        assertThat(gate.isDown()).as("Redis answered; it refused the command").isFalse();
    }

    @Test
    void withoutAGateARequestThreadGoesToRedissonAsEveryThreadDoes() throws Exception {
        @SuppressWarnings({"unchecked", "rawtypes"})
        MfaStateMachineServiceImpl service = new MfaStateMachineServiceImpl(mock(StateMachineFactory.class),
                mock(StateMachinePersister.class), redisson, new StateMachineProperties());
        String session = session();
        onRequestThread();

        assertThat(service.tryAcquireLock(session, 750, TimeUnit.MILLISECONDS)).isTrue();
        service.releaseLock(session);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private MfaStateMachineServiceImpl service(RedissonClient client) {
        return new MfaStateMachineServiceImpl(mock(StateMachineFactory.class), mock(StateMachinePersister.class), client,
                new StateMachineProperties(), gate);
    }

    private String session() {
        String session = "outage-" + UUID.randomUUID();
        keys.add(key(session));
        return session;
    }

    private static String key(String session) {
        return ApplicationNamespace.key(LOCK_PREFIX + session);
    }

    private static RLock lock(String session) {
        return redisson.getLock(key(session));
    }

    private static void onRequestThread() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }
}
