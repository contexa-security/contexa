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
        @DisplayName("Should have DistributedInfraConfiguration inner class with distributed mode condition")
        void shouldHaveDistributedInnerClass() throws Exception {
            Class<?> distributedClass = Class.forName(
                    CoreInfrastructureAutoConfiguration.class.getName() + "$DistributedInfraConfiguration");

            ConditionalOnProperty annotation = distributedClass
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(annotation).isNotNull();
            assertThat(annotation.name()).containsExactly("contexa.infrastructure.mode");
            assertThat(annotation.havingValue()).isEqualTo("distributed");
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
