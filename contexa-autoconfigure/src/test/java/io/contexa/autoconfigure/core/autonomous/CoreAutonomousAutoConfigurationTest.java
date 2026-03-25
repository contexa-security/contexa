package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.context.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.SessionNarrativeCollector;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.lang.reflect.Method;

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

    @Nested
    @DisplayName("Session narrative wiring")
    class SessionNarrativeWiring {

        @Test
        @DisplayName("Should declare SessionNarrativeCollector bean method backed by SecurityContextDataStore")
        void shouldDeclareSessionNarrativeCollectorBeanMethod() throws Exception {
            Method method = CoreAutonomousAutoConfiguration.class
                    .getDeclaredMethod("sessionNarrativeCollector", SecurityContextDataStore.class);

            assertThat(method.getReturnType()).isEqualTo(SessionNarrativeCollector.class);
        }

        @Test
        @DisplayName("Should wire SessionNarrativeCollector into canonical context provider and prompt template")
        void shouldWireSessionNarrativeCollectorIntoRuntimePath() {
            Method canonicalProviderMethod = findMethod("canonicalSecurityContextProvider");
            Method promptTemplateMethod = findMethod("securityPromptTemplate");

            assertThat(canonicalProviderMethod.toGenericString()).contains("SessionNarrativeCollector");
            assertThat(promptTemplateMethod.toGenericString()).contains("CanonicalSecurityContextProvider");
            assertThat(promptTemplateMethod.toGenericString()).contains("PromptContextComposer");
        }

        private Method findMethod(String name) {
            return java.util.Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Method not found: " + name));
        }
    }

    @Nested
    @DisplayName("Work profile wiring")
    class WorkProfileWiring {

        @Test
        @DisplayName("Should declare ProtectableWorkProfileCollector bean method backed by SecurityContextDataStore")
        void shouldDeclareProtectableWorkProfileCollectorBeanMethod() throws Exception {
            Method method = CoreAutonomousAutoConfiguration.class
                    .getDeclaredMethod("protectableWorkProfileCollector", SecurityContextDataStore.class);

            assertThat(method.getReturnType()).isEqualTo(ProtectableWorkProfileCollector.class);
        }

        @Test
        @DisplayName("Should wire ProtectableWorkProfileCollector into canonical context provider")
        void shouldWireProtectableWorkProfileCollectorIntoRuntimePath() {
            Method canonicalProviderMethod = findMethod("canonicalSecurityContextProvider");

            assertThat(canonicalProviderMethod.toGenericString()).contains("ProtectableWorkProfileCollector");
        }

        private Method findMethod(String name) {
            return java.util.Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Method not found: " + name));
        }
    }
}
