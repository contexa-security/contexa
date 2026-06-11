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
package io.contexa.autoconfigure.core.session;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.generator.HttpSessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.RedisSessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import io.contexa.contexacore.infra.session.impl.HttpSessionMfaRepository;
import io.contexa.contexacore.infra.session.impl.RedisMfaRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Arrays;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(name = "io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration")
@EnableConfigurationProperties(AuthContextProperties.class)
public class CoreSessionAutoConfiguration {

    private final Environment environment;

    public CoreSessionAutoConfiguration(Environment environment) {
        this.environment = environment;
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.data.redis.core.StringRedisTemplate")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    static class RedisSessionConfiguration {

        @Bean
        @Primary
        @ConditionalOnMissingBean(MfaSessionRepository.class)
        public MfaSessionRepository mfaSessionRepository(
                StringRedisTemplate redisTemplate,
                AuthContextProperties properties) {
            RedisMfaRepository repository = new RedisMfaRepository(
                    redisTemplate,
                    new RedisSessionIdGenerator(redisTemplate),
                    properties);
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());
            return repository;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(name = "stringRedisTemplate")
    static class StandaloneSessionConfiguration {

        @Bean
        @Primary
        @ConditionalOnMissingBean(MfaSessionRepository.class)
        public MfaSessionRepository mfaSessionRepository(AuthContextProperties properties) {
            HttpSessionMfaRepository fallback = new HttpSessionMfaRepository(new HttpSessionIdGenerator());
            fallback.setSessionTimeout(properties.getMfa().getSessionTimeout());
            return fallback;
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionIdGenerator sessionIdGenerator() {
        return new HttpSessionIdGenerator();
    }

    private String detectEnvironmentType() {
        if (isClusterEnvironment()) {
            return "CLUSTER";
        } else if (isDevelopmentEnvironment()) {
            return "DEVELOPMENT";
        } else {
            return "SINGLE_SERVER";
        }
    }

    private boolean isClusterEnvironment() {
        boolean hasSpringCloud = environment.containsProperty("spring.cloud.kubernetes.enabled") ||
                environment.containsProperty("spring.cloud.consul.enabled") ||
                environment.containsProperty("eureka.client.enabled");

        boolean hasRedis = environment.containsProperty("spring.redis.host") ||
                environment.containsProperty("spring.redis.cluster.nodes");

        boolean hasLoadBalancer = environment.containsProperty("server.forward-headers-strategy");

        return hasSpringCloud || (hasRedis && hasLoadBalancer);
    }

    private boolean isDevelopmentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.stream(activeProfiles)
                .anyMatch(profile -> profile.contains("dev") ||
                        profile.contains("test") ||
                        profile.contains("local"));
    }
}
