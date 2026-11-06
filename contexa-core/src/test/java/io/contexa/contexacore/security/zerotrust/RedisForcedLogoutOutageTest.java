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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.RedisClusterConnection;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisSentinelConnection;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * On a real Redis (CONTEXA_TEST_REDIS_PORT) that a test can cut off: a forced logout that Redis does not
 * take while it is away is applied once it is back, and it stays on record that it waited. Only the keys of this test's
 * users are removed: other tests and other people may share the Redis.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@ExtendWith(OutputCaptureExtension.class)
class RedisForcedLogoutOutageTest {

    /** The Redis a test can cut off: the connections of a real one, refused while it is down. */
    private static final class SwitchedConnections implements RedisConnectionFactory {

        private final RedisConnectionFactory real;
        private final AtomicInteger asked = new AtomicInteger();
        private volatile boolean down;

        private SwitchedConnections(RedisConnectionFactory real) {
            this.real = real;
        }

        @Override
        public RedisConnection getConnection() {
            asked.incrementAndGet();
            if (down) {
                throw new RedisConnectionFailureException("Redis is cut off for this test");
            }
            return real.getConnection();
        }

        @Override
        public boolean getConvertPipelineAndTxResults() {
            return real.getConvertPipelineAndTxResults();
        }

        @Override
        public RedisClusterConnection getClusterConnection() {
            return real.getClusterConnection();
        }

        @Override
        public RedisSentinelConnection getSentinelConnection() {
            return real.getSentinelConnection();
        }

        @Override
        public DataAccessException translateExceptionIfPossible(RuntimeException ex) {
            return real.translateExceptionIfPossible(ex);
        }
    }

    private static LettuceConnectionFactory lettuce;

    private final String user = "logout-" + UUID.randomUUID();
    private final String otherUser = "logout-" + UUID.randomUUID();
    private final String session = "session-" + UUID.randomUUID();
    private final String otherSession = "session-" + UUID.randomUUID();
    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final ContexaStores stores = new ContexaStores();
    private SwitchedConnections connections;
    private RedisTemplate<String, Object> redis;
    private RedisZeroTrustSecurityService service;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        lettuce = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        lettuce.afterPropertiesSet();
    }

    @AfterAll
    static void disconnect() {
        if (lettuce != null) {
            lettuce.destroy();
        }
    }

    @BeforeEach
    void setUp() {
        connections = new SwitchedConnections(lettuce);
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connections);
        service = new RedisZeroTrustSecurityService(redis, mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(),
                actions);
        service.setContexaStores(stores);
        service.setAudit(() -> audit);
        stores.redis().watchWith(() -> {
            if (connections.down) {
                throw new QueryTimeoutException("still cut off");
            }
        });
    }

    @AfterEach
    void removeWrittenKeys() {
        connections.down = false;
        stores.destroy();
        for (String id : List.of(user, otherUser, session, otherSession)) {
            Set<String> keys = redis.keys("*" + id + "*");
            if (keys != null && !keys.isEmpty()) {
                redis.delete(keys);
            }
        }
    }

    private void redisGoesAway() {
        connections.down = true;
        stores.redis().fail(new QueryTimeoutException("no answer"));
    }

    private void redisComesBack() {
        connections.down = false;
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> !stores.redis().isDown());
    }

    private void theSessionIsEnded(String sessionId) {
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> service.isSessionInvalidated(sessionId));
    }

    @Test
    void aForcedLogoutRedisDidNotTakeIsAppliedOnceItIsBack() {
        service.doRegisterSession(user, session, null);
        redisGoesAway();

        assertThatCode(() -> service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED")).doesNotThrowAnyException();
        assertThat(service.forcedLogoutsWaiting()).isEqualTo(1);

        redisComesBack();

        theSessionIsEnded(session);
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> service.forcedLogoutsWaiting() == 0);
    }

    @Test
    void itReachesTheIdsOfTheSessionListAsTheForcedLogoutDoes() {
        redis.opsForSet().add(ZeroTrustRedisKeys.userSessions(user), session);
        redisGoesAway();
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        redisComesBack();

        theSessionIsEnded(session);
    }

    @Test
    void aSessionOpenedDuringTheOutageAndKnownAfterItEndsToo() {
        redisGoesAway();
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");
        connections.down = false;
        service.doRegisterSession(user, session, null);
        connections.down = true;

        redisComesBack();

        theSessionIsEnded(session);
    }

    @Test
    void theDecisionsOfTheLogoutGoWithIt() {
        redisGoesAway();
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");
        verify(actions, never()).removeLogoutData(user);

        redisComesBack();

        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> verify(actions).removeLogoutData(user));
    }

    @Test
    void aNameSpelledAsAConsoleKeyTakesTheDecisionsOfNoConsoleSession() {
        String named = "console::" + user;
        redisGoesAway();
        service.invalidateAllUserSessions(named, "ACCOUNT_DISABLED");

        redisComesBack();

        Awaitility.await().atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> verify(actions).removeLogoutData(ZeroTrustUserKey.person(named)));
        verify(actions, never()).removeLogoutData(named);
    }

    @Test
    void aForcedLogoutRedisTookWaitsForNothing() {
        service.doRegisterSession(user, session, null);

        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        assertThat(service.isSessionInvalidated(session)).isTrue();
        assertThat(service.forcedLogoutsWaiting()).isZero();
    }

    @Test
    void theSweepAppliesWhatNoGateReported() {
        service.doRegisterSession(user, session, null);
        connections.down = true;
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");
        connections.down = false;

        service.removeExpiredEntries();

        assertThat(service.isSessionInvalidated(session)).isTrue();
        assertThat(service.forcedLogoutsWaiting()).isZero();
    }

    @Test
    void theSweepLeavesRedisAloneWhileItIsDown() {
        redisGoesAway();
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");
        int asked = connections.asked.get();

        service.removeExpiredEntries();

        assertThat(connections.asked.get()).isEqualTo(asked);
        assertThat(service.forcedLogoutsWaiting()).isEqualTo(1);
    }

    @Test
    void whatAFailedPassDidNotReachWaitsForTheNextOne() {
        service.doRegisterSession(user, session, null);
        service.doRegisterSession(otherUser, otherSession, null);
        connections.down = true;
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");
        service.invalidateAllUserSessions(otherUser, "ACCOUNT_DISABLED");

        service.removeExpiredEntries();
        assertThat(service.forcedLogoutsWaiting()).isEqualTo(2);

        connections.down = false;
        service.removeExpiredEntries();

        assertThat(service.isSessionInvalidated(session)).isTrue();
        assertThat(service.isSessionInvalidated(otherSession)).isTrue();
        assertThat(service.forcedLogoutsWaiting()).isZero();
    }

    @Test
    void theRecordSaysItWaitedAndThatItWasApplied() {
        redisGoesAway();
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        redisComesBack();

        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> service.forcedLogoutsWaiting() == 0);
        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, atLeastOnce()).recordAsync(records.capture());
        assertThat(records.getAllValues()).extracting(AuditRecord::getAction)
                .containsExactly("FORCED_LOGOUT_WAITING_FOR_REDIS", "FORCED_LOGOUT_APPLIED_AFTER_OUTAGE");
        assertThat(records.getAllValues()).extracting(AuditRecord::getPrincipalName).containsOnly(user);
    }

    @Test
    void aFailureThatIsNoOutageIsNotKeptForLater() {
        RedisTemplate<String, Object> broken = mock();
        when(broken.opsForSet()).thenThrow(new IllegalStateException("a bug"));
        RedisZeroTrustSecurityService failing = new RedisZeroTrustSecurityService(broken, mock(ThreatScoreUtil.class),
                new SecurityZeroTrustProperties(), actions);

        failing.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        assertThat(failing.forcedLogoutsWaiting()).isZero();
    }

    @Test
    void aStopWithLogoutsStillWaitingSaysSo(CapturedOutput output) {
        redisGoesAway();
        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        service.destroy();

        assertThat(output).contains("1 forced logouts were still waiting for Redis");
    }

    @Test
    void aStopWithNothingWaitingSaysNothing(CapturedOutput output) {
        service.destroy();

        assertThat(output).doesNotContain("forced logouts were still waiting");
    }

    @Test
    void withoutARecordKeeperTheLogoutStillWaits() {
        service.setAudit(() -> null);
        redisGoesAway();

        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        assertThat(service.forcedLogoutsWaiting()).isEqualTo(1);
        verify(audit, never()).recordAsync(any());
    }
}
