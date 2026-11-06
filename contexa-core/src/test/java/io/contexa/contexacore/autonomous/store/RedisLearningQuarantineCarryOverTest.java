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

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A learning quarantine has no expiry, so one made before the application was given a name is carried to the keys of its
 * name, once. Keys of their own in a shared Redis: nothing here flushes it.
 */
class RedisLearningQuarantineCarryOverTest {

    private static final String EARLIER_KEY = "security:autonomous:learning:quarantine";
    private static final String APPLICATION = "shop";

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;

    private final String agent = "agent:carry-" + UUID.randomUUID();
    private final String delegation = "delegation:carry-" + UUID.randomUUID();
    private final RedisSecurityContextDataStore firstServer = new RedisSecurityContextDataStore(redis);
    private final RedisSecurityContextDataStore secondServer = new RedisSecurityContextDataStore(redis);

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void clean() {
        redis.opsForSet().remove(EARLIER_KEY, agent, delegation);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            firstServer.setLearningQuarantined(agent, false);
            firstServer.setLearningQuarantined(delegation, false);
            redis.delete(ApplicationNamespace.key(EARLIER_KEY + ":carried"));
        }
    }

    private void earlierQuarantine(String... scopes) {
        redis.opsForSet().add(EARLIER_KEY, (Object[]) scopes);
    }

    @Test
    @DisplayName("a named application takes the scopes quarantined under the earlier key as its own, and leaves the earlier key")
    void theEarlierScopesAreCarried() {
        earlierQuarantine(agent, delegation);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(firstServer.learningQuarantined(agent)).as("before the carry-over").isFalse();

            assertThat(firstServer.carryOverLearningQuarantine()).isEqualTo(2);

            assertThat(firstServer.learningQuarantined(agent)).isTrue();
            assertThat(secondServer.learningQuarantineScopes()).contains(agent, delegation);
        }
        assertThat(redis.opsForSet().isMember(EARLIER_KEY, agent)).as("the earlier key stays").isTrue();
    }

    @Test
    @DisplayName("it is done once: a scope the operator releases afterwards stays released, whichever server asks")
    void aReleasedScopeStaysReleased() {
        earlierQuarantine(agent, delegation);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            firstServer.carryOverLearningQuarantine();
            firstServer.setLearningQuarantined(agent, false);
            firstServer.setLearningQuarantined(delegation, false);

            assertThat(secondServer.carryOverLearningQuarantine()).isZero();
            assertThat(firstServer.carryOverLearningQuarantine()).isZero();

            assertThat(secondServer.learningQuarantined(agent)).isFalse();
            assertThat(secondServer.learningQuarantined(delegation)).isFalse();
        }
    }

    @Test
    @DisplayName("what the application quarantined itself is kept, and the carried scopes are added to it")
    void itsOwnScopesAreKept() {
        earlierQuarantine(delegation);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            firstServer.setLearningQuarantined(agent, true);

            assertThat(firstServer.carryOverLearningQuarantine()).isEqualTo(1);

            assertThat(secondServer.learningQuarantineScopes()).contains(agent, delegation);
        }
    }

    @Test
    @DisplayName("an application without a name has no earlier key: it carries nothing and changes nothing")
    void anUnnamedApplicationCarriesNothing() {
        earlierQuarantine(agent);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(firstServer.carryOverLearningQuarantine()).isZero();

            assertThat(firstServer.learningQuarantined(agent)).as("the key it always read").isTrue();
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(redis.hasKey(ApplicationNamespace.key(EARLIER_KEY + ":carried"))).isFalse();
            assertThat(firstServer.learningQuarantined(agent)).as("and a named one has still carried nothing").isFalse();
        }
    }

    @Test
    @DisplayName("with no earlier quarantine nothing is carried, and the application is not marked as done")
    void nothingEarlierCarriesNothing() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(firstServer.carryOverLearningQuarantine()).isZero();
            assertThat(firstServer.learningQuarantineScopes()).isEmpty();
            assertThat(redis.hasKey(ApplicationNamespace.key(EARLIER_KEY + ":carried"))).isFalse();
        }

        earlierQuarantine(agent);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(firstServer.carryOverLearningQuarantine()).as("one made there later is carried").isEqualTo(1);
        }
    }
}
