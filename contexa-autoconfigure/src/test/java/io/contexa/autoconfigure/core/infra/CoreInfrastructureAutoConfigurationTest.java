package io.contexa.autoconfigure.core.infra;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests CoreInfrastructureAutoConfiguration conditional annotations.
 * Full ApplicationContextRunner tests are not feasible due to @Import
 * pulling in AsyncConfig/ApplicationConfig with transitive dependencies.
 */
@DisplayName("CoreInfrastructureAutoConfiguration")
class CoreInfrastructureAutoConfigurationTest {

    @Nested
    @DisplayName("Conditional annotations")
    class ConditionalAnnotations {

        @Test
        @DisplayName("Should have @ConditionalOnProperty for contexa.enabled with matchIfMissing=true")
        void shouldHaveEnabledCondition() {
            ConditionalOnProperty annotation = CoreInfrastructureAutoConfiguration.class
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(annotation).isNotNull();
            assertThat(annotation.prefix()).isEqualTo("contexa");
            assertThat(annotation.name()).containsExactly("enabled");
            assertThat(annotation.havingValue()).isEqualTo("true");
            assertThat(annotation.matchIfMissing()).isTrue();
        }

        @Test
        @DisplayName("Should have DistributedRedisInfraConfiguration and DistributedKafkaInfraConfiguration inner classes with distributed mode condition")
        void shouldHaveDistributedInnerClasses() throws Exception {
            Class<?> redisClass = Class.forName(
                    CoreInfrastructureAutoConfiguration.class.getName() + "$DistributedRedisInfraConfiguration");

            ConditionalOnProperty redisAnnotation = redisClass
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(redisAnnotation).isNotNull();
            assertThat(redisAnnotation.name()).containsExactly("contexa.infrastructure.mode");
            assertThat(redisAnnotation.havingValue()).isEqualTo("distributed");

            Class<?> kafkaClass = Class.forName(
                    CoreInfrastructureAutoConfiguration.class.getName() + "$DistributedKafkaInfraConfiguration");

            ConditionalOnProperty kafkaAnnotation = kafkaClass
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(kafkaAnnotation).isNotNull();
            assertThat(kafkaAnnotation.name()).containsExactly("contexa.infrastructure.mode");
            assertThat(kafkaAnnotation.havingValue()).isEqualTo("distributed");
        }

        @Test
        @DisplayName("Should have StandaloneAsyncConfiguration inner class")
        void shouldHaveStandaloneInnerClass() throws Exception {
            Class<?> standaloneClass = Class.forName(
                    CoreInfrastructureAutoConfiguration.class.getName() + "$StandaloneAsyncConfiguration");

            assertThat(standaloneClass).isNotNull();
        }
    }
}
