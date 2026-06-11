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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.lock.InMemoryDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("DistributedLockService registration across modes")
class DistributedLockServiceRegistrationTest {

    @Nested
    @DisplayName("Distributed mode")
    class DistributedMode {

        @Test
        @DisplayName("Should register RedisDistributedLockService when mode=distributed and RedisTemplate present")
        void distributedMode_registersRedisImplementation() {
            new ApplicationContextRunner()
                    .withUserConfiguration(CoreAutonomousAutoConfiguration.DistributedRepositoryConfiguration.class)
                    .withBean("redisTemplate", RedisTemplate.class, () -> mock(RedisTemplate.class))
                    .withBean("stringRedisTemplate", StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
                    .withBean(SecurityZeroTrustProperties.class, SecurityZeroTrustProperties::new)
                    .withPropertyValues("contexa.infrastructure.mode=distributed")
                    .run(context -> {
                        assertThat(context).hasSingleBean(DistributedLockService.class);
                        assertThat(context.getBean(DistributedLockService.class))
                                .isInstanceOf(RedisDistributedLockService.class);
                    });
        }
    }

    @Nested
    @DisplayName("Standalone mode")
    class StandaloneMode {

        @Test
        @DisplayName("Should register InMemoryDistributedLockService via default @Bean when no other candidate exists")
        void standaloneMode_registersInMemoryImplementation() {
            new ApplicationContextRunner()
                    .withUserConfiguration(StandaloneLockTestConfiguration.class)
                    .run(context -> {
                        assertThat(context).hasSingleBean(DistributedLockService.class);
                        assertThat(context.getBean(DistributedLockService.class))
                                .isInstanceOf(InMemoryDistributedLockService.class);
                    });
        }
    }

    @org.springframework.context.annotation.Configuration
    static class StandaloneLockTestConfiguration {
        @org.springframework.context.annotation.Bean
        @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(DistributedLockService.class)
        public InMemoryDistributedLockService inMemoryDistributedLockService() {
            return new InMemoryDistributedLockService();
        }
    }
}
