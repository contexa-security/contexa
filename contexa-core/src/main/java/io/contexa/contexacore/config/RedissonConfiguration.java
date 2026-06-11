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
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnClass(name = "org.redisson.api.RedissonClient")
@ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
public class RedissonConfiguration {

    private final RedisProperties redisProperties;

    @Bean
    @ConditionalOnMissingBean(type = "org.redisson.api.RedissonClient")
    public RedissonClient redissonClient() {
        Config config = new Config();

        String address = String.format("redis://%s:%d", redisProperties.getHost(), redisProperties.getPort());
        java.time.Duration timeout = redisProperties.getTimeout() != null ? redisProperties.getTimeout() : java.time.Duration.ofMillis(5000);
        config.useSingleServer()
            .setAddress(address)
            .setPassword(null)
            .setDatabase(0)
            .setConnectionMinimumIdleSize(2)
            .setConnectionPoolSize(10)
            .setIdleConnectionTimeout(10000)
            .setConnectTimeout((int) timeout.toMillis())
            .setTimeout(3000)
            .setRetryAttempts(3)
            .setPingConnectionInterval(0);

        return Redisson.create(config);
    }
}