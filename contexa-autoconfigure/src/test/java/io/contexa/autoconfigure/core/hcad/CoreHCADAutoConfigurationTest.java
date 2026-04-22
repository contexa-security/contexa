package io.contexa.autoconfigure.core.hcad;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.lang.reflect.Method;

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
        @DisplayName("Should have @ConditionalOnProperty for hcad.enabled with matchIfMissing=true")
        void shouldHaveHcadEnabledCondition() {
            ConditionalOnProperty annotation = CoreHCADAutoConfiguration.class
                    .getAnnotation(ConditionalOnProperty.class);

            assertThat(annotation).isNotNull();
            assertThat(annotation.prefix()).isEqualTo("hcad");
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
        @DisplayName("Should declare in-memory standalone fallback beans")
        void shouldDeclareStandaloneFallbackBeans() throws Exception {
            assertInMemoryFallback("hcadDataStore");
            assertInMemoryFallback("baselineDataStore");
            assertInMemoryFallback("analysisTriggerStateRepository");
        }

        private void assertInMemoryFallback(String methodName) throws Exception {
            Method method = CoreHCADAutoConfiguration.class.getDeclaredMethod(methodName);

            assertThat(method.getReturnType().getSimpleName()).startsWith("InMemory");
            assertThat(method.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
        }
    }
}
