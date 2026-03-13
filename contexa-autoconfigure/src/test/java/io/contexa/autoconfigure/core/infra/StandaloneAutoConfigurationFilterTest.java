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

    @Nested
    @DisplayName("Standalone mode filtering")
    class StandaloneModeFiltering {

        @Test
        @DisplayName("Should exclude Redis auto-configuration in standalone mode")
        void shouldExcludeRedis() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {"org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }

        @Test
        @DisplayName("Should exclude Kafka auto-configuration in standalone mode")
        void shouldExcludeKafka() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {"org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }

        @Test
        @DisplayName("Should exclude Redisson auto-configuration in standalone mode")
        void shouldExcludeRedisson() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {"org.redisson.spring.starter.RedissonAutoConfiguration"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
        }

        @Test
        @DisplayName("Should allow non-Redis/Kafka/Redisson configs in standalone mode")
        void shouldAllowOtherConfigs() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
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
            StandaloneAutoConfigurationFilter filter = createFilter(null);
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
            StandaloneAutoConfigurationFilter filter = createFilter("distributed");
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
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {null, "org.springframework.boot.autoconfigure.web.WebAutoConfig"};

            boolean[] result = filter.match(classes, metadata);

            // null entries pass through (result[i] = true)
            assertThat(result[0]).isTrue();
            assertThat(result[1]).isTrue();
        }

        @Test
        @DisplayName("Should handle case-insensitive pattern matching")
        void shouldMatchCaseInsensitive() {
            StandaloneAutoConfigurationFilter filter = createFilter("standalone");
            String[] classes = {"com.example.REDIS_Configuration", "com.example.KafkaProducer"};

            boolean[] result = filter.match(classes, metadata);

            assertThat(result[0]).isFalse();
            assertThat(result[1]).isFalse();
        }
    }
}
