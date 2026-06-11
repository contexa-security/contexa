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
package io.contexa.autoconfigure.core.infra;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("StandaloneAutoConfigurationFilter")
class StandaloneAutoConfigurationFilterTest {

    private final AutoConfigurationMetadata metadata = mock(AutoConfigurationMetadata.class);

    private StandaloneAutoConfigurationFilter createFilter(String mode) {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter();
        MockEnvironment env = new MockEnvironment();
        if (mode != null) {
            env.setProperty("contexa.infrastructure.mode", mode);
        }
        filter.setEnvironment(env);
        return filter;
    }

    private StandaloneAutoConfigurationFilter createActiveFilter(String mode) {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter();
        MockEnvironment env = new MockEnvironment();
        if (mode != null) {
            env.setProperty("contexa.infrastructure.mode", mode);
        }
        env.setProperty("contexa.ai.security.mode", "SANDBOX");
        filter.setEnvironment(env);
        return filter;
    }

    @Nested
    @DisplayName("Standalone mode filtering")
    class StandaloneModeFiltering {

        @Test
        @DisplayName("Should exclude Redis auto-configuration in standalone mode")
        void shouldExcludeRedis() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("standalone");
            String[] classes = {"org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }

        @Test
        @DisplayName("Should exclude Kafka auto-configuration in standalone mode")
        void shouldExcludeKafka() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("standalone");
            String[] classes = {"org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }

        @Test
        @DisplayName("Should exclude Redisson auto-configuration in standalone mode")
        void shouldExcludeRedisson() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("standalone");
            String[] classes = {"org.redisson.spring.starter.RedissonAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }

        @Test
        @DisplayName("Should allow non-Redis/Kafka/Redisson configs in standalone mode")
        void shouldAllowOtherConfigs() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("standalone");
            String[] classes = {
                    "org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration",
                    "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration"
            };

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isTrue();
            assertThat(result[1]).isTrue();
        }

        @Test
        @DisplayName("Should default to standalone when mode property is not set")
        void shouldDefaultToStandalone() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter(null);
            String[] classes = {"org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }
    }

    @Nested
    @DisplayName("Distributed mode passthrough")
    class DistributedModePassthrough {

        @Test
        @DisplayName("Should allow all auto-configurations in distributed mode")
        void shouldAllowAllInDistributed() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("distributed");
            String[] classes = {
                    "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
                    "org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration",
                    "org.redisson.spring.starter.RedissonAutoConfiguration",
                    "org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration"
            };

            boolean[] result = filter.match(classes, metadata);

            assertThat(result).containsExactly(true, true, true, true);
        }
    }

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle null class name gracefully")
        void shouldHandleNullClassName() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("standalone");
            String[] classes = {null, "org.springframework.boot.autoconfigure.web.WebAutoConfig"};

            boolean[] result = filter.match(classes, metadata);

            // null entries pass through (result[i] = true)
            assertThat(result[0]).isTrue();
            assertThat(result[1]).isTrue();
        }

        @Test
        @DisplayName("Should handle case-insensitive pattern matching")
        void shouldMatchCaseInsensitive() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("standalone");
            String[] classes = {"com.example.REDIS_Configuration", "com.example.KafkaProducer"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
            assertThat(result[1]).isFalse();
        }
    }

    @Nested
    @DisplayName("Contexa platform activation")
    class ContexaPlatformActivation {

        @Test
        @DisplayName("Should exclude Contexa auto-configurations when @EnableAISecurity did not activate the platform")
        void shouldExcludeContexaAutoConfigurationsWhenPlatformIsInactive() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {
                    "io.contexa.autoconfigure.core.CoreDataAutoConfiguration",
                    "io.contexa.contexacommon.cache.ContexaCacheAutoConfiguration",
                    "io.contexa.contexacore.config.CoreSecurityAutoConfiguration",
                    "io.contexa.contexaidentity.security.core.asep.autoconfigure.AsepAutoConfiguration",
                    "org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration"
            };

            boolean[] result = filter.match(classes, metadata);

            assertThat(result).containsExactly(false, false, false, false, true);
        }

        @Test
        @DisplayName("Should not filter customer Redis/Kafka auto-configurations when @EnableAISecurity did not activate the platform")
        void shouldNotFilterCustomerInfrastructureAutoConfigurationsWhenPlatformIsInactive() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {
                    "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
                    "org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration",
                    "org.redisson.spring.starter.RedissonAutoConfiguration"
            };

            boolean[] result = filter.match(classes, metadata);

            assertThat(result).containsExactly(true, true, true);
        }

        @Test
        @DisplayName("Should allow Contexa auto-configurations after @EnableAISecurity activates the platform")
        void shouldAllowContexaAutoConfigurationsWhenPlatformIsActive() {
            StandaloneAutoConfigurationFilter filter = createActiveFilter("distributed");
            String[] classes = {
                    "io.contexa.autoconfigure.core.CoreDataAutoConfiguration",
                    "io.contexa.contexacommon.cache.ContexaCacheAutoConfiguration",
                    "io.contexa.contexacore.config.CoreSecurityAutoConfiguration",
                    "io.contexa.contexaidentity.security.core.asep.autoconfigure.AsepAutoConfiguration"
            };

            boolean[] result = filter.match(classes, metadata);

            assertThat(result).containsExactly(true, true, true, true);
        }
    }
}
