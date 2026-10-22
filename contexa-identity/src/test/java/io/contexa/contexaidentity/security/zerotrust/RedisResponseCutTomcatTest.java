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
package io.contexa.contexaidentity.security.zerotrust;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.config.redis.ContexaJsonRedisSerializer;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockedStateProbe;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.test.annotation.DirtiesContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * RT-6 in distributed mode, on a Redis of its own (Testcontainers, never the developer's Redis): the Redis decision
 * store and the Redisson broadcaster of the server, and a second instance (a Redisson client of its own) that decides
 * the BLOCK. A BLOCK decided on the other instance cuts the server's stream, and so does one whose signal the server
 * missed, from the decision in force.
 */
@SpringBootTest(classes = {ResponseCutTomcatTestSupport.Web.class, RedisResponseCutTomcatTest.Stores.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RedisResponseCutTomcatTest extends ResponseCutTomcatTestSupport {

    private static final String TOPIC = "contexa:security:block-signal";

    private static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.2-alpine"))
            .withExposedPorts(6379);

    static {
        REDIS.start();
    }

    @Autowired
    private RedissonClient serverClient;

    static RedissonClient client() {
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + REDIS.getHost() + ":" + REDIS.getMappedPort(6379));
        return Redisson.create(config);
    }

    static BlockedStateProbe probe(ZeroTrustActionRepository decisions) {
        return userId -> decisions.getCurrentAction(userId, null) == ZeroTrustAction.BLOCK;
    }

    @Test
    @DisplayName("a BLOCK decided on another instance cuts the server's stream once its signal arrives")
    void aBlockDecidedOnAnotherInstanceCutsTheStream() throws Exception {
        RedissonClient other = client();
        try {
            BlockingDecisionRegistry otherSignals = new BlockingDecisionRegistry(other, probe(decisions),
                    Duration.ofMillis(500));
            String user = newUser();
            String id = UUID.randomUUID().toString();
            CountDownLatch started = new CountDownLatch(1);
            CompletableFuture<Reading> reading = CompletableFuture.supplyAsync(
                    () -> read(user, "/cut/sync?rows=400&everyMs=20&id=" + id, started));
            assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();

            decideBlock(decisions, otherSignals, user);
            await().atMost(Duration.ofSeconds(2)).pollInterval(Duration.ofMillis(1)).until(() -> signals.isBlocked(user));
            long arrivedAt = System.nanoTime();

            assertCut(reading.get(20, TimeUnit.SECONDS), progressOf(id), arrivedAt);
        } finally {
            other.shutdown();
        }
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    @DisplayName("a BLOCK whose signal the server missed still cuts the stream within 1 s, from the decision in force")
    void aMissedSignalStillCutsTheStream() throws Exception {
        RedissonClient other = client();
        try {
            // The server's subscription drops: it no longer hears the topic.
            serverClient.getTopic(TOPIC).removeAllListeners();
            BlockingDecisionRegistry otherSignals = new BlockingDecisionRegistry(other, probe(decisions),
                    Duration.ofMillis(500));
            String user = newUser();
            String id = UUID.randomUUID().toString();
            CountDownLatch started = new CountDownLatch(1);
            CompletableFuture<Reading> reading = CompletableFuture.supplyAsync(
                    () -> read(user, "/cut/async?rows=400&everyMs=20&id=" + id, started));
            assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();

            decideBlock(decisions, otherSignals, user);
            long blockedAt = System.nanoTime();

            Reading cut = reading.get(20, TimeUnit.SECONDS);
            assertCut(cut, progressOf(id), blockedAt + TimeUnit.SECONDS.toNanos(1));
        } finally {
            other.shutdown();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Stores {

        @Bean(destroyMethod = "shutdown")
        RedissonClient serverClient() {
            return client();
        }

        @Bean(destroyMethod = "destroy")
        LettuceConnectionFactory redisConnections() {
            LettuceConnectionFactory connections = new LettuceConnectionFactory(
                    new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379)));
            connections.afterPropertiesSet();
            return connections;
        }

        @Bean
        ZeroTrustActionRedisRepository decisions(LettuceConnectionFactory connections) {
            return new ZeroTrustActionRedisRepository(objectTemplate(connections), stringTemplate(connections));
        }

        @Bean
        BlockingDecisionRegistry signals(RedissonClient serverClient, ZeroTrustActionRepository decisions) {
            return new BlockingDecisionRegistry(serverClient, probe(decisions), Duration.ofMillis(500));
        }

        /** The production Redis template: string keys, Contexa's typed JSON values. */
        private static RedisTemplate<String, Object> objectTemplate(LettuceConnectionFactory connections) {
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
            GenericJackson2JsonRedisSerializer json = new ContexaJsonRedisSerializer(
                    ContexaJsonRedisSerializer.activateDefaultTyping(mapper));
            StringRedisSerializer strings = new StringRedisSerializer();
            RedisTemplate<String, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(connections);
            template.setKeySerializer(strings);
            template.setHashKeySerializer(strings);
            template.setValueSerializer(json);
            template.setHashValueSerializer(json);
            template.setDefaultSerializer(json);
            template.setEnableTransactionSupport(false);
            template.afterPropertiesSet();
            return template;
        }

        private static StringRedisTemplate stringTemplate(LettuceConnectionFactory connections) {
            StringRedisTemplate template = new StringRedisTemplate();
            template.setConnectionFactory(connections);
            template.afterPropertiesSet();
            return template;
        }
    }
}
