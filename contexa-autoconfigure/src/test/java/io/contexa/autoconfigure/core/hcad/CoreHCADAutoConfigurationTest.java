package io.contexa.autoconfigure.core.hcad;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests CoreHCADAutoConfiguration conditional annotations and inner class structure.
 */
@DisplayName("CoreHCADAutoConfiguration")
class CoreHCADAutoConfigurationTest {

    @Nested
    @DisplayName("Conditional annotations")
    class ConditionalAnnotations {

        @Test
        @DisplayName("Should have @ConditionalOnProperty for contexa.hcad.enabled with matchIfMissing=true")
        void shouldHaveHcadEnabledCondition() {
            ConditionalOnProperty annotation = CoreHCADAutoConfiguration.class
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(annotation).isNotNull();
            assertThat(annotation.prefix()).isEqualTo("contexa.hcad");
            assertThat(annotation.name()).containsExactly("enabled");
            assertThat(annotation.havingValue()).isEqualTo("true");
            assertThat(annotation.matchIfMissing()).isTrue();
        }

        @Test
        @DisplayName("Should have DistributedHCADConfig inner class with @ConditionalOnBean(RedisTemplate)")
        void shouldHaveDistributedInnerClass() throws Exception {
            Class<?> distributedClass = Class.forName(
                    CoreHCADAutoConfiguration.class.getName() + "$DistributedHCADConfig");

            assertThat(distributedClass).isNotNull();
            assertThat(distributedClass.getAnnotation(
                    org.springframework.boot.autoconfigure.condition.ConditionalOnBean.class))
                    .isNotNull();
        }

        @Test
        @DisplayName("Should have StandaloneHCADConfig inner class with @ConditionalOnMissingBean(RedisTemplate)")
        void shouldHaveStandaloneInnerClass() throws Exception {
            Class<?> standaloneClass = Class.forName(
                    CoreHCADAutoConfiguration.class.getName() + "$StandaloneHCADConfig");

            assertThat(standaloneClass).isNotNull();
            assertThat(standaloneClass.getAnnotation(
                    org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean.class))
                    .isNotNull();
        }
    }
}
