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

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.AdjustableClock;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-16 (PR-66): a passed step-up is a fact of the context it was passed in (the session, its address and its client),
 * kept for an hour, as the user's MFA mark is. Both stores answer alike: every scenario runs in memory and on a real
 * Redis (set CONTEXA_BACKLOG_REDIS_PORT), under keys of its own.
 */
class ChallengeVerifiedStoreTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final Instant PASSED_AT = Instant.parse("2026-11-05T10:15:30Z");

    private static LettuceConnectionFactory factory;
    private static RedisTemplate<String, Object> redisTemplate;

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(factory);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    private static String user() {
        return "q16-" + UUID.randomUUID();
    }

    private static SecurityContextDataStore redis() {
        return new RedisSecurityContextDataStore(redisTemplate);
    }

    private static void assertItIsAFactOfItsContext(SecurityContextDataStore store) {
        String user = user();
        store.markChallengeVerified(user, "context-a", PASSED_AT);

        assertThat(store.getChallengeVerifiedAt(user, "context-a")).isEqualTo(PASSED_AT);
        assertThat(store.getChallengeVerifiedAt(user, "context-b")).as("another session of the user").isNull();
        assertThat(store.getChallengeVerifiedAt(user(), "context-a")).as("another user").isNull();
    }

    @Test
    void inMemoryItIsAFactOfItsContext() {
        assertItIsAFactOfItsContext(new InMemorySecurityContextDataStore());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisItIsAFactOfItsContext() {
        assertItIsAFactOfItsContext(redis());
    }

    private static void assertTwoContextsKeepTheirOwn(SecurityContextDataStore store) {
        String user = user();
        store.markChallengeVerified(user, "context-a", PASSED_AT);
        store.markChallengeVerified(user, "context-b", PASSED_AT.plusSeconds(60));

        assertThat(store.getChallengeVerifiedAt(user, "context-a")).isEqualTo(PASSED_AT);
        assertThat(store.getChallengeVerifiedAt(user, "context-b")).isEqualTo(PASSED_AT.plusSeconds(60));
    }

    @Test
    void inMemoryTwoContextsKeepTheirOwn() {
        assertTwoContextsKeepTheirOwn(new InMemorySecurityContextDataStore());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTwoContextsKeepTheirOwn() {
        assertTwoContextsKeepTheirOwn(redis());
    }

    private static void assertADeletedAccountLeavesNone(SecurityContextDataStore store) {
        String user = user();
        store.markChallengeVerified(user, "context-a", PASSED_AT);
        store.markChallengeVerified(user, "context-b", PASSED_AT);

        store.deleteUserData(user);

        assertThat(store.getChallengeVerifiedAt(user, "context-a")).isNull();
        assertThat(store.getChallengeVerifiedAt(user, "context-b")).isNull();
    }

    @Test
    void inMemoryADeletedAccountLeavesNone() {
        assertADeletedAccountLeavesNone(new InMemorySecurityContextDataStore());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisADeletedAccountLeavesNone() {
        assertADeletedAccountLeavesNone(redis());
    }

    private static void assertNothingIsAskedOfNoContext(SecurityContextDataStore store) {
        String user = user();
        store.markChallengeVerified(user, null, PASSED_AT);
        store.markChallengeVerified(user, " ", PASSED_AT);

        assertThat(store.getChallengeVerifiedAt(user, null)).isNull();
        assertThat(store.getChallengeVerifiedAt(user, " ")).isNull();
    }

    @Test
    void inMemoryNothingIsAskedOfNoContext() {
        assertNothingIsAskedOfNoContext(new InMemorySecurityContextDataStore());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisNothingIsAskedOfNoContext() {
        assertNothingIsAskedOfNoContext(redis());
    }

    @Test
    void inMemoryItLastsTheTimeOfTheUsersMfaMark() {
        AdjustableClock clock = new AdjustableClock();
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(Duration.ofHours(1),
                Duration.ofHours(1), Duration.ofHours(1), clock);
        String user = user();
        store.markChallengeVerified(user, "context-a", PASSED_AT);

        clock.advance(Duration.ofMinutes(59));
        assertThat(store.getChallengeVerifiedAt(user, "context-a")).isEqualTo(PASSED_AT);

        clock.advance(Duration.ofMinutes(2));
        assertThat(store.getChallengeVerifiedAt(user, "context-a")).isNull();
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisItLastsTheTimeOfTheUsersMfaMark() {
        SecurityContextDataStore store = redis();
        String user = user();
        store.markChallengeVerified(user, "context-a", PASSED_AT);

        Long left = redisTemplate.getExpire(ZeroTrustRedisKeys.authenticationChallengeVerified(user), TimeUnit.SECONDS);

        assertThat(left).isBetween(Duration.ofMinutes(59).toSeconds(), Duration.ofHours(1).toSeconds());
        store.deleteUserData(user);
    }

    /** A context marked long ago is past its hour although another context of the user keeps the key alive. */
    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAContextPastItsTimeIsGoneWhileAnotherKeepsTheKey() {
        SecurityContextDataStore store = redis();
        String user = user();
        String key = ZeroTrustRedisKeys.authenticationChallengeVerified(user);
        long pastMs = System.currentTimeMillis() - 1_000L;
        redisTemplate.opsForHash().put(key, "context-a", pastMs + ":" + PASSED_AT.toEpochMilli());
        store.markChallengeVerified(user, "context-b", PASSED_AT);

        assertThat(store.getChallengeVerifiedAt(user, "context-a")).isNull();
        assertThat(store.getChallengeVerifiedAt(user, "context-b")).isEqualTo(PASSED_AT);
        store.deleteUserData(user);
    }
}
