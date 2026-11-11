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
package io.contexa.contexacore.infra.redis;

import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * On a real Redis: the messages Contexa's listener container receives are handled on threads that say they are Contexa's. The container
 * names its threads after its bean unless it is given an executor, and a name of a bean is not what an operator reads as Contexa's in
 * a thread dump.
 */
class ContexaRedisListenerThreadNamesTest {

    private LettuceConnectionFactory connections;
    private RedisTemplate<String, Object> template;
    private RedisMessageListenerContainer container;

    @BeforeEach
    void connect() {
        TestStores.Redis server = TestStores.redis();
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connections.afterPropertiesSet();
        template = new RedisTemplate<>();
        template.setConnectionFactory(connections);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.afterPropertiesSet();
    }

    @AfterEach
    void disconnect() throws Exception {
        if (container != null) {
            container.destroy();
        }
        if (connections != null) {
            connections.destroy();
        }
    }

    @Test
    void theApprovalListenerContainerHandlesMessagesOnContexasThreads() throws Exception {
        // the container as Contexa makes it (without an approval notifier it listens to nothing of its own), and a listener of the test's
        container = new UnifiedRedisConfiguration().redisMessageListenerContainer(connections, null, template);
        CompletableFuture<String> handledOn = new CompletableFuture<>();
        String channel = UnifiedRedisConfiguration.soarApprovalChannel();
        container.addMessageListener((message, pattern) -> handledOn.complete(Thread.currentThread().getName()), new ChannelTopic(channel));
        container.afterPropertiesSet();
        container.start();

        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (!handledOn.isDone() && System.nanoTime() < until) {
            template.convertAndSend(channel, "approval");
            try {
                handledOn.get(200, TimeUnit.MILLISECONDS);
            } catch (TimeoutException notYet) {
                // the subscription is made in the background: send again
            }
        }

        assertThat(handledOn.get(1, TimeUnit.SECONDS)).startsWith("contexa-redis-message-listener-");
    }
}
