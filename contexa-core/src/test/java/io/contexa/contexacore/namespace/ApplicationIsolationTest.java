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
package io.contexa.contexacore.namespace;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.baseline.store.RedisBaselineDataStore;
import io.contexa.contexacore.autonomous.repository.RedisProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.store.RedisBlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.security.async.RedisAsyncSecurityContextProvider;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Two applications on one Redis: what one application keeps is never read, changed or removed by the other, and the
 * servers of one application keep sharing all of it. Keys of their own in a shared Redis: nothing here flushes it.
 */
class ApplicationIsolationTest {

    private static final String SHOP = "shop";
    private static final String CLINIC = "clinic";
    private static final String CONTEXT = "context-hash-1";

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;
    private static StringRedisTemplate strings;

    private final String user = "iso-user-" + UUID.randomUUID();
    private final String session = "iso-session-" + UUID.randomUUID();
    private final String clientIp = "10.77." + ThreadLocalRandom.current().nextInt(256) + "." + ThreadLocalRandom.current().nextInt(256);
    private final List<String> keysToRemove = new ArrayList<>();

    /** Two servers of an application, each with stores of its own over the one Redis. */
    private final ZeroTrustActionRedisRepository firstServerActions = new ZeroTrustActionRedisRepository(redis, strings);
    private final ZeroTrustActionRedisRepository secondServerActions = new ZeroTrustActionRedisRepository(redis, strings);
    private final RedisSecurityContextDataStore firstServerContext = new RedisSecurityContextDataStore(redis);
    private final RedisSecurityContextDataStore secondServerContext = new RedisSecurityContextDataStore(redis);
    private final RedisBaselineDataStore baselines = new RedisBaselineDataStore(redis);
    private final RedisProtectableRapidReentryRepository reentry = new RedisProtectableRapidReentryRepository(strings);
    private final RedisBlockMfaStateStore blockMfa = new RedisBlockMfaStateStore(strings, firstServerActions);
    private final RedisDistributedLockService locks = new RedisDistributedLockService(redis);
    private final RedisAsyncSecurityContextProvider async = new RedisAsyncSecurityContextProvider(redis);

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        strings = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void removeWhatTheTestWrote() {
        for (String name : new String[]{SHOP, CLINIC, ""}) {
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
                try {
                    firstServerActions.removeAllUserData(user);
                    firstServerContext.deleteUserData(user);
                    baselines.deleteUserBaseline(user);
                    locks.forceUnlock("iso-lock-" + user);
                    async.removeAuthentication(user, session);
                } catch (RuntimeException cleanupFailure) {
                    // Cleanup is best effort: the keys are unique to this test.
                }
            }
        }
        keysToRemove.forEach(strings::delete);
    }

    @Test
    @DisplayName("a BLOCK of one application does not block the same user name in another, and its servers share it")
    void aBlockStaysInItsApplication() {
        as(SHOP, () -> firstServerActions.setBlockedFlag(user));

        assertThat(as(SHOP, () -> secondServerActions.getCurrentAction(user, CONTEXT)))
                .as("the other server of the same application").isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(as(CLINIC, () -> firstServerActions.getCurrentAction(user, CONTEXT)))
                .as("another application").isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(as(CLINIC, () -> secondServerActions.getCurrentAction(user, CONTEXT)))
                .isNotEqualTo(ZeroTrustAction.BLOCK);

        as(SHOP, () -> secondServerActions.removeBlockedFlag(user));
        assertThat(as(SHOP, () -> firstServerActions.getCurrentAction(user, CONTEXT)))
                .as("a release on one server is a release on the other").isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a decision of one application is not the decision of another")
    void aDecisionStaysInItsApplication() {
        as(SHOP, () -> firstServerActions.saveActionWithPrevious(user, ZeroTrustAction.CHALLENGE, CONTEXT));

        assertThat(as(SHOP, () -> secondServerActions.getActionFromHash(user))).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(as(CLINIC, () -> firstServerActions.getActionFromHash(user))).isNull();
        assertThat(as(CLINIC, () -> firstServerActions.getLastVerifiedAction(user))).isNull();
    }

    @Test
    @DisplayName("removing a user's data in one application leaves the same user name in another as it was")
    void aRemovalStaysInItsApplication() {
        as(SHOP, () -> firstServerActions.setBlockedFlag(user));
        as(CLINIC, () -> firstServerActions.setBlockedFlag(user));

        as(SHOP, () -> firstServerActions.removeAllUserData(user));

        assertThat(as(SHOP, () -> firstServerActions.getCurrentAction(user, CONTEXT))).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(as(CLINIC, () -> firstServerActions.getCurrentAction(user, CONTEXT))).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("sessions, decisions and the state of a sign-in are kept per application and shared by its servers")
    void contextStaysInItsApplication() {
        as(SHOP, () -> firstServerContext.addSessionDecision(session, "ALLOW|1"));
        as(SHOP, () -> firstServerContext.addSessionAction(session, "GET /orders"));
        as(SHOP, () -> firstServerContext.markMfaVerified(user));
        as(SHOP, () -> firstServerContext.trackUserSession(user, session));
        as(SHOP, () -> firstServerContext.recordLoginFailure(user, "10.0.0.1", System.currentTimeMillis()));

        assertThat(as(SHOP, () -> secondServerContext.getRecentSessionDecisions(session, 10))).containsExactly("ALLOW|1");
        assertThat(as(SHOP, () -> secondServerContext.getRecentSessionActions(session, 10))).containsExactly("GET /orders");
        assertThat(as(SHOP, () -> secondServerContext.isMfaVerified(user))).isTrue();
        assertThat(as(SHOP, () -> secondServerContext.getUserSessions(user))).contains(session);

        assertThat(as(CLINIC, () -> firstServerContext.getRecentSessionDecisions(session, 10))).isNullOrEmpty();
        assertThat(as(CLINIC, () -> firstServerContext.getRecentSessionActions(session, 10))).isNullOrEmpty();
        assertThat(as(CLINIC, () -> firstServerContext.isMfaVerified(user))).isFalse();
        assertThat(as(CLINIC, () -> firstServerContext.getUserSessions(user))).isNullOrEmpty();
        assertThat(as(CLINIC, () -> firstServerContext.getRecentLoginFailureCount(user, "10.0.0.1", 0L,
                System.currentTimeMillis()))).isZero();
    }

    @Test
    @DisplayName("an event one application claimed is still free for another, and the version of the authorities is its own")
    void eventClaimsAndAuthorityVersionsStayInTheirApplication() {
        String eventId = "iso-event-" + UUID.randomUUID();
        assertThat(as(SHOP, () -> firstServerContext.claimEventProcessing(eventId)))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);

        assertThat(as(CLINIC, () -> firstServerContext.claimEventProcessing(eventId)))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);

        long clinicBefore = as(CLINIC, firstServerContext::authoritiesVersion);
        as(SHOP, firstServerContext::advanceAuthoritiesVersion);
        assertThat(as(CLINIC, firstServerContext::authoritiesVersion)).isEqualTo(clinicBefore);
        as(SHOP, () -> firstServerContext.releaseEventProcessing(eventId));
        as(CLINIC, () -> firstServerContext.releaseEventProcessing(eventId));
    }

    @Test
    @DisplayName("a learning quarantine is the application's own")
    void learningQuarantineStaysInItsApplication() {
        String scope = "iso-scope-" + UUID.randomUUID();
        as(SHOP, () -> firstServerContext.setLearningQuarantined(scope, true));
        try {
            assertThat(as(SHOP, () -> secondServerContext.learningQuarantined(scope))).isTrue();
            assertThat(as(CLINIC, () -> firstServerContext.learningQuarantined(scope))).isFalse();
        } finally {
            as(SHOP, () -> firstServerContext.setLearningQuarantined(scope, false));
        }
    }

    @Test
    @DisplayName("a baseline is learned per application, and deleting a user's baseline in one leaves the other's")
    void baselinesStayInTheirApplication() {
        as(SHOP, () -> baselines.saveUserBaseline(user, BaselineVector.builder().userId(user).updateCount(5L)
                .avgTrustScore(0.9).build()));
        as(CLINIC, () -> baselines.saveUserBaseline(user, BaselineVector.builder().userId(user).updateCount(7L)
                .avgTrustScore(0.5).build()));

        assertThat(as(SHOP, () -> baselines.getUserBaseline(user)).getUpdateCount()).isEqualTo(5L);
        assertThat(as(CLINIC, () -> baselines.getUserBaseline(user)).getUpdateCount()).isEqualTo(7L);

        as(SHOP, () -> baselines.deleteUserBaseline(user));

        assertThat(as(SHOP, () -> baselines.getUserBaseline(user))).isNull();
        assertThat(as(CLINIC, () -> baselines.getUserBaseline(user))).isNotNull();
    }

    @Test
    @DisplayName("a rapid re-entry guard, a verified step-up and a lock are the application's own")
    void guardsAndLocksStayInTheirApplication() {
        String resource = "/orders/" + UUID.randomUUID();
        assertThat(as(SHOP, () -> reentry.tryAcquire(user, CONTEXT, resource, Duration.ofSeconds(30)))).isTrue();
        assertThat(as(SHOP, () -> reentry.tryAcquire(user, CONTEXT, resource, Duration.ofSeconds(30)))).isFalse();
        assertThat(as(CLINIC, () -> reentry.tryAcquire(user, CONTEXT, resource, Duration.ofSeconds(30)))).isTrue();

        as(SHOP, () -> blockMfa.setVerified(user, CONTEXT));
        assertThat(as(SHOP, () -> blockMfa.isVerified(user, CONTEXT))).isTrue();
        assertThat(as(CLINIC, () -> blockMfa.isVerified(user, CONTEXT))).isFalse();

        String lock = "iso-lock-" + user;
        assertThat(as(SHOP, () -> locks.tryLock(lock, "shop-owner", Duration.ofSeconds(30)))).isTrue();
        assertThat(as(SHOP, () -> locks.isLocked(lock))).isTrue();
        assertThat(as(CLINIC, () -> locks.isLocked(lock))).isFalse();
        assertThat(as(CLINIC, () -> locks.tryLock(lock, "clinic-owner", Duration.ofSeconds(30)))).isTrue();
        as(CLINIC, () -> locks.unlock(lock, "clinic-owner"));
        as(SHOP, () -> locks.unlock(lock, "shop-owner"));
    }

    @Test
    @DisplayName("the authentication kept for an asynchronous thread is the application's own")
    void asyncAuthenticationStaysInItsApplication() {
        as(SHOP, () -> async.saveAuthenticationForAsync(authentication(), session));

        assertThat(as(SHOP, () -> async.getAuthenticationByUserId(user))).isPresent();
        assertThat(as(CLINIC, () -> async.getAuthenticationByUserId(user))).isEmpty();
        assertThat(as(CLINIC, () -> async.getAuthenticationBySessionId(session))).isEmpty();
    }

    @Test
    @DisplayName("every key a named application's stores write is the key they always wrote under ctxa:<name>:")
    void everyKeyIsTheOldKeyUnderThePrefix() {
        List<String> named = writtenBy(SHOP);
        List<String> unnamed = writtenBy("");

        assertThat(named).as("keys written by the named application").hasSizeGreaterThan(20);
        assertThat(named).allMatch(key -> key.startsWith("ctxa:" + SHOP + ":"));
        assertThat(unnamed).as("an application without a name keeps its keys").noneMatch(key -> key.startsWith("ctxa:"));
        assertThat(named.stream().map(key -> key.substring(("ctxa:" + SHOP + ":").length())).sorted().toList())
                .as("the same keys, the prefix aside").isEqualTo(unnamed.stream().sorted().toList());
    }

    /** The keys the stores add to Redis while an application of that name runs through them; they are removed after. */
    private List<String> writtenBy(String applicationName) {
        // Some keys are one for all users: left by an earlier test, they would not be new.
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(applicationName)) {
            for (String shared : new String[]{"security:autonomous:baseline:user:index",
                    "security:context:authentication:failures:keys", "security:context:authentication:failures:lost"}) {
                strings.delete(ApplicationNamespace.key(shared));
            }
        }
        List<String> before = allKeys();
        writeEverything(applicationName);
        List<String> added = new ArrayList<>(allKeys());
        added.removeAll(before);
        added.forEach(strings::delete);
        return added;
    }

    private static List<String> allKeys() {
        List<String> found = new ArrayList<>();
        try (Cursor<String> cursor = strings.scan(ScanOptions.scanOptions().match("*").count(500).build())) {
            cursor.forEachRemaining(found::add);
        }
        return found;
    }

    private void writeEverything(String applicationName) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(applicationName)) {
            firstServerActions.setBlockedFlag(user);
            firstServerActions.saveActionWithPrevious(user, ZeroTrustAction.CHALLENGE, CONTEXT);
            firstServerActions.setBlockMfaPending(user);
            firstServerActions.incrementBlockMfaFailCount(user);
            firstServerContext.addSessionDecision(session, "ALLOW|1");
            firstServerContext.addSessionAction(session, "GET /orders");
            firstServerContext.setSessionStartedAt(session, 1L);
            firstServerContext.setSessionRisk(session, 0.2d);
            firstServerContext.markMfaVerified(user);
            firstServerContext.trackUserSession(user, session);
            firstServerContext.recordLoginFailure(user, clientIp, System.currentTimeMillis());
            firstServerContext.setLastRequestTime(user, 1L);
            firstServerContext.setPreviousPath(user, "/orders");
            firstServerContext.addWorkProfileObservation("tenant", user, "obs");
            baselines.saveUserBaseline(user, BaselineVector.builder().userId(user).updateCount(1L).build());
            reentry.tryAcquire(user, CONTEXT, "/orders/" + session, Duration.ofSeconds(30));
            blockMfa.setVerified(user, CONTEXT);
            locks.tryLock("iso-lock-" + user, "owner", Duration.ofSeconds(30));
            async.saveAuthenticationForAsync(authentication(), session);
        }
    }

    private UsernamePasswordAuthenticationToken authentication() {
        return UsernamePasswordAuthenticationToken.authenticated(user, null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    private static <T> T as(String applicationName, Supplier<T> action) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(applicationName)) {
            return action.get();
        }
    }

    private static void as(String applicationName, Runnable action) {
        as(applicationName, () -> {
            action.run();
            return null;
        });
    }
}
