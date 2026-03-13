package io.contexa.autoconfigure.core.autonomous;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests CoreAutonomousAutoConfiguration conditional annotations and mode switching structure.
 */
@DisplayName("CoreAutonomousAutoConfiguration")
class CoreAutonomousAutoConfigurationTest {

    @Nested
    @DisplayName("Conditional annotations")
    class ConditionalAnnotations {

        @Test
        @DisplayName("Should have @ConditionalOnProperty for contexa.autonomous.enabled with matchIfMissing=true")
        void shouldHaveAutonomousEnabledCondition() {
            ConditionalOnProperty annotation = CoreAutonomousAutoConfiguration.class
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(annotation).isNotNull();
            assertThat(annotation.prefix()).isEqualTo("contexa.autonomous");
            assertThat(annotation.name()).containsExactly("enabled");
            assertThat(annotation.havingValue()).isEqualTo("true");
            assertThat(annotation.matchIfMissing()).isTrue();
        }
    }

    @Nested
    @DisplayName("STANDALONE/DISTRIBUTED mode switching")
    class ModeSwitching {

        @Test
        @DisplayName("Should have DistributedRepositoryConfiguration with distributed mode + RedisTemplate conditions")
        void shouldHaveDistributedConfigWithDualConditions() throws Exception {
            Class<?> distributedClass = Class.forName(
                    CoreAutonomousAutoConfiguration.class.getName() + "$DistributedRepositoryConfiguration");

            ConditionalOnProperty propertyAnnotation = distributedClass
                    .getAnnotation(ConditionalOnProperty.class);
            ConditionalOnBean beanAnnotation = distributedClass
                    .getAnnotation(ConditionalOnBean.class);

            assertThat(propertyAnnotation).isNotNull();
            assertThat(propertyAnnotation.name()).containsExactly("contexa.infrastructure.mode");
            assertThat(propertyAnnotation.havingValue()).isEqualTo("distributed");
            assertThat(beanAnnotation).isNotNull();
        }

        @Test
        @DisplayName("Should have StandaloneRepositoryConfiguration with standalone mode and matchIfMissing=true")
        void shouldHaveStandaloneConfigWithDefaultMode() throws Exception {
            Class<?> standaloneClass = Class.forName(
                    CoreAutonomousAutoConfiguration.class.getName() + "$StandaloneRepositoryConfiguration");

            ConditionalOnProperty annotation = standaloneClass
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(annotation).isNotNull();
            assertThat(annotation.name()).containsExactly("contexa.infrastructure.mode");
            assertThat(annotation.havingValue()).isEqualTo("standalone");
            assertThat(annotation.matchIfMissing()).isTrue();
        }
    }
}
