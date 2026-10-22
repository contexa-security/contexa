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
package io.contexa.contexacore.autonomous.blocking;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * The distributed broadcaster under the shared contract on a Redis of its own (Testcontainers, never the developer's
 * Redis), and across two instances, each a Redisson client of its own (RT-2): a BLOCK published by one cuts the other's
 * response, a BLOCK the other missed (its subscription dropped) is still cut from the decision in force, and a release
 * reaches the other.
 */
@Testcontainers
class RedisBlockingSignalBroadcasterContractTest extends BlockingSignalBroadcasterContractTest {

    private static final String TOPIC = "contexa:security:block-signal";

    @Container
    private static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.2-alpine"))
            .withExposedPorts(6379);

    private static RedissonClient first;
    private static RedissonClient second;
    private static LettuceConnectionFactory connections;
    private static ZeroTrustActionRedisRepository store;

    @BeforeAll
    static void connect() {
        first = client();
        second = client();
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(REDIS.getHost(),
                REDIS.getMappedPort(6379)));
        connections.afterPropertiesSet();
        store = new ZeroTrustActionRedisRepository(RedisTestTemplates.newProductionAlignedRedisTemplate(connections),
                RedisTestTemplates.newStringRedisTemplate(connections));
    }

    @AfterAll
    static void disconnect() {
        first.shutdown();
        second.shutdown();
        connections.destroy();
    }

    private static RedissonClient client() {
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + REDIS.getHost() + ":" + REDIS.getMappedPort(6379));
        return Redisson.create(config);
    }

    @Override
    protected BlockingSignalBroadcaster create(BlockedStateProbe probe, Duration probeInterval, LongSupplier clock) {
        return new BlockingDecisionRegistry(first, probe, probeInterval, clock);
    }

    /** Its own publications come back on the topic: the state holds for 200 ms once they arrived. */
    @Override
    protected void settle(BlockingSignalBroadcaster signals, String user, boolean blocked) {
        await().atMost(Duration.ofSeconds(3)).during(Duration.ofMillis(200))
                .until(() -> signals.isBlocked(user) == blocked);
    }

    private static BlockedStateProbe storeProbe() {
        return userId -> store.getCurrentAction(userId, null) == ZeroTrustAction.BLOCK;
    }

    @Test
    @DisplayName("a BLOCK published by one instance cuts a response of the other instance")
    void aBlockFromOneInstanceCutsTheOther() {
        BlockingDecisionRegistry publisher = new BlockingDecisionRegistry(first, storeProbe(), Duration.ofMillis(500));
        BlockingDecisionRegistry other = new BlockingDecisionRegistry(second, storeProbe(), Duration.ofMillis(500));
        String user = user();
        long started = System.nanoTime();

        publisher.registerBlockAndAwait(user);

        await().atMost(Duration.ofSeconds(2)).until(() -> other.isBlocked(user));
        assertThat(other.shouldCut(user, started)).isTrue();
        assertThat(other.getBlockAction(user)).isEqualTo("BLOCK");
    }

    @Test
    @DisplayName("a BLOCK the other instance missed is still cut there from the decision in force within 1 s")
    void aMissedBlockIsCutFromTheDecisionInForce() {
        RedissonClient deaf = client();
        try {
            BlockingDecisionRegistry other = new BlockingDecisionRegistry(deaf, storeProbe(), Duration.ofMillis(500));
            // The other instance's subscription drops: it no longer hears the topic.
            deaf.getTopic(TOPIC).removeAllListeners();
            BlockingDecisionRegistry publisher = new BlockingDecisionRegistry(first, storeProbe(),
                    Duration.ofMillis(500));
            String user = user();
            long started = System.nanoTime();

            // Same order as SecurityDecisionEnforcementHandler applies a BLOCK decision.
            store.setBlockedFlag(user);
            publisher.registerBlockAndAwait(user);

            assertThat(other.isBlocked(user)).as("the signal did not arrive").isFalse();
            await().atMost(Duration.ofSeconds(1)).until(() -> other.shouldCut(user, started));
        } finally {
            deaf.shutdown();
        }
    }

    @Test
    @DisplayName("a release published by one instance reaches the other")
    void aReleaseReachesTheOtherInstance() {
        BlockingDecisionRegistry publisher = new BlockingDecisionRegistry(first, storeProbe(), Duration.ofMillis(500));
        BlockingDecisionRegistry other = new BlockingDecisionRegistry(second, storeProbe(), Duration.ofMillis(500));
        String user = user();
        publisher.registerBlockAndAwait(user);
        await().atMost(Duration.ofSeconds(2)).until(() -> other.isBlocked(user));

        publisher.registerUnblock(user);

        await().atMost(Duration.ofSeconds(2)).until(() -> !other.isBlocked(user));
        assertThat(other.shouldCut(user, System.nanoTime())).isFalse();
    }
}
