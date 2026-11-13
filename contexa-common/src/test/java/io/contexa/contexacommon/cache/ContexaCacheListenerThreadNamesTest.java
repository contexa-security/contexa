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
package io.contexa.contexacommon.cache;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * On a real Redis (CONTEXA_TEST_REDIS_PORT): the invalidations of Contexa's hybrid cache are handled on threads that say they are
 * Contexa's, not on threads named after the bean of the container.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_REDIS_PORT", matches = ".+")
class ContexaCacheListenerThreadNamesTest {

    private LettuceConnectionFactory connections;
    private RedisMessageListenerContainer container;

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
    void theInvalidationsAreHandledOnContexasThreads() throws Exception {
        int port = Integer.parseInt(System.getenv("CONTEXA_TEST_REDIS_PORT"));
        assertThat(port).as("not the Redis a developer runs for themselves").isNotEqualTo(6379);
        // contexa-common sits below the module of TestStores, so it keeps TestStores' rule here: the port must be set (the class runs
        // only then), and the host is the loopback address when it is not
        String named = System.getenv("CONTEXA_TEST_REDIS_HOST");
        String host = named == null || named.isBlank() ? "127.0.0.1" : named;
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(host, port));
        connections.afterPropertiesSet();
        StringRedisTemplate template = new StringRedisTemplate(connections);

        CompletableFuture<String> handledOn = new CompletableFuture<>();
        MessageListenerAdapter adapter = new MessageListenerAdapter((MessageListener) (message, pattern) ->
                handledOn.complete(Thread.currentThread().getName()));
        ContexaCacheProperties properties = new ContexaCacheProperties();
        container = new ContexaCacheAutoConfiguration.DistributedCacheConfig().contexaCacheListenerContainer(connections, adapter, properties);
        container.afterPropertiesSet();
        container.start();

        String channel = properties.getPubsub().qualifiedChannel();
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (!handledOn.isDone() && System.nanoTime() < until) {
            template.convertAndSend(channel, "invalidate");
            try {
                handledOn.get(200, TimeUnit.MILLISECONDS);
            } catch (TimeoutException notYet) {
                // the subscription is made in the background: send again
            }
        }

        assertThat(handledOn.get(1, TimeUnit.SECONDS)).startsWith("contexa-cache-listener-");
    }
}
