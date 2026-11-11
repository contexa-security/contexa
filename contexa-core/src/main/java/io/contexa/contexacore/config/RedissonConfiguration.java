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
package io.contexa.contexacore.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisConnectionDetails;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Fallback;
import org.springframework.util.StringUtils;

import java.time.Duration;

/**
 * Contexa's Redisson client, connected the way the application's own Redis is: user name, password, database, TLS, and standalone, sentinel
 * or cluster as Spring Boot reads them from {@code spring.data.redis.*} (the url form included). It connects when it is first used, so a
 * Redis that is down when the application starts does not stop the application from starting.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnClass(name = "org.redisson.api.RedissonClient")
@ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
public class RedissonConfiguration {

    private final RedisProperties redisProperties;

    /**
     * Contexa's own client, whether or not the application has one: Contexa's locks and signals, and the clean-up of its MFA
     * flows, never go through a client the application configured (its server, database, codec or timeouts). It is a
     * fallback candidate, so the application's own client is the one a plain injection point of the application is given,
     * and an application without one is given this one, as before. Contexa's injection points name it.
     */
    @Bean(name = "contexaRedissonClient")
    @Fallback
    @ConditionalOnMissingBean(name = "contexaRedissonClient")
    public RedissonClient redissonClient(ObjectProvider<RedisConnectionDetails> connectionDetails) {
        return Redisson.create(configFor(connectionDetails.getIfAvailable(), redisProperties));
    }

    /** The Redisson configuration for the connection the application describes; {@code details} may be absent, then the properties are used. */
    static Config configFor(RedisConnectionDetails details, RedisProperties properties) {
        Duration timeout = properties.getTimeout() != null ? properties.getTimeout() : Duration.ofMillis(5000);
        Config config = new Config();
        config.setLazyInitialization(true);
        if (details != null && details.getCluster() != null) {
            RedisConnectionDetails.Cluster cluster = details.getCluster();
            String scheme = cluster.getSslBundle() != null ? "rediss" : "redis";
            var servers = config.useClusterServers().setConnectTimeout((int) timeout.toMillis()).setTimeout(3000).setRetryAttempts(3)
                    .setUsername(StringUtils.hasText(details.getUsername()) ? details.getUsername() : null)
                    .setPassword(StringUtils.hasText(details.getPassword()) ? details.getPassword() : null);
            for (RedisConnectionDetails.Node node : cluster.getNodes()) {
                servers.addNodeAddress(address(scheme, node.host(), node.port()));
            }
        } else if (details != null && details.getSentinel() != null) {
            RedisConnectionDetails.Sentinel sentinel = details.getSentinel();
            String scheme = sentinel.getSslBundle() != null ? "rediss" : "redis";
            var servers = config.useSentinelServers().setMasterName(sentinel.getMaster()).setDatabase(sentinel.getDatabase())
                    .setConnectTimeout((int) timeout.toMillis()).setTimeout(3000).setRetryAttempts(3)
                    .setUsername(StringUtils.hasText(sentinel.getUsername()) ? sentinel.getUsername() : null)
                    .setPassword(StringUtils.hasText(sentinel.getPassword()) ? sentinel.getPassword() : null);
            for (RedisConnectionDetails.Node node : sentinel.getNodes()) {
                servers.addSentinelAddress(address(scheme, node.host(), node.port()));
            }
        } else {
            String host;
            int port;
            int database;
            boolean tls;
            String username;
            String password;
            if (details != null && details.getStandalone() != null) {
                host = details.getStandalone().getHost();
                port = details.getStandalone().getPort();
                database = details.getStandalone().getDatabase();
                tls = details.getStandalone().getSslBundle() != null;
                username = details.getUsername();
                password = details.getPassword();
            } else {
                host = properties.getHost();
                port = properties.getPort();
                database = properties.getDatabase();
                tls = properties.getSsl().isEnabled();
                username = properties.getUsername();
                password = properties.getPassword();
            }
            config.useSingleServer()
                    .setAddress(address(tls ? "rediss" : "redis", host, port))
                    .setUsername(StringUtils.hasText(username) ? username : null)
                    .setPassword(StringUtils.hasText(password) ? password : null)
                    .setDatabase(database)
                    .setConnectionMinimumIdleSize(2)
                    .setConnectionPoolSize(10)
                    .setIdleConnectionTimeout(10000)
                    .setConnectTimeout((int) timeout.toMillis())
                    .setTimeout(3000)
                    .setRetryAttempts(3)
                    .setPingConnectionInterval(0);
        }
        return config;
    }

    /** The port is written as text, never formatted: a default locale with other digits must not change an address. */
    private static String address(String scheme, String host, int port) {
        return scheme + "://" + host + ":" + port;
    }
}
