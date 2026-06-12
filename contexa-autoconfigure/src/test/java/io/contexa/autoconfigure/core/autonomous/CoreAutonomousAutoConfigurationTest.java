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

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import java.lang.reflect.Method;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

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

        @Test
        @DisplayName("Should only create VectorStoreCacheLayer when VectorStore is available")
        void shouldGuardVectorStoreCacheLayerWithVectorStoreBean() throws Exception {
            Method method = CoreAutonomousAutoConfiguration.class
                    .getDeclaredMethod("vectorStoreCacheLayer", VectorStore.class, TieredStrategyProperties.class);

            assertThat(method.getReturnType()).isEqualTo(VectorStoreCacheLayer.class);
            ConditionalOnBean annotation = method.getAnnotation(ConditionalOnBean.class);
            assertThat(annotation).isNotNull();
            assertThat(annotation.value()).containsExactly(VectorStore.class);
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
        @DisplayName("Should declare in-memory standalone fallback beans")
        void shouldDeclareStandaloneFallbackBeans() throws Exception {
            assertInMemoryFallback("inMemoryZeroTrustActionRepository");
            assertInMemoryFallback("inMemoryProtectableRapidReentryRepository");
            assertInMemoryFallback("inMemoryDistributedLockService");
            assertInMemoryFallback("inMemorySecurityContextDataStore");
        }

        private void assertInMemoryFallback(String methodName) throws Exception {
            Method method = CoreAutonomousAutoConfiguration.class.getDeclaredMethod(methodName);

            assertThat(method.getReturnType().getSimpleName()).startsWith("InMemory");
            assertThat(method.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
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
            Method promptTemplateMethod = findMethod("securityDecisionStandardPromptTemplate");

            assertThat(canonicalProviderMethod.toGenericString()).contains("SessionNarrativeCollector");
            assertThat(promptTemplateMethod.toGenericString()).contains("CanonicalSecurityContextProvider");
            assertThat(promptTemplateMethod.toGenericString()).contains("PromptContextComposer");
        }

        private Method findMethod(String name) {
            return Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
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
            return Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Method not found: " + name));
        }
    }

    @Nested
    @DisplayName("Detection strategy wiring")
    class DetectionStrategyWiring {

        @Test
        @DisplayName("Should wire SaasDetectionStrategyPackService into contextual and expert strategies")
        void shouldWireDetectionStrategyPackServiceIntoRuntimeStrategies() {
            Method contextualStrategyMethod = findMethod("contextualStrategy");
            Method expertStrategyMethod = findMethod("expertStrategy");

            assertThat(contextualStrategyMethod.toGenericString()).contains("SaasDetectionStrategyPackService");
            assertThat(expertStrategyMethod.toGenericString()).contains("SaasDetectionStrategyPackService");
        }

        private Method findMethod(String name) {
            return Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Method not found: " + name));
        }
    }

    @Nested
    @DisplayName("Role scope wiring")
    class RoleScopeWiring {

        @Test
        @DisplayName("Should declare RoleScopeCollector bean method backed by SecurityContextDataStore")
        void shouldDeclareRoleScopeCollectorBeanMethod() throws Exception {
            Method method = CoreAutonomousAutoConfiguration.class
                    .getDeclaredMethod("roleScopeCollector", SecurityContextDataStore.class);

            assertThat(method.getReturnType()).isEqualTo(RoleScopeCollector.class);
        }

        @Test
        @DisplayName("Should wire RoleScopeCollector into canonical context provider")
        void shouldWireRoleScopeCollectorIntoRuntimePath() {
            Method canonicalProviderMethod = findMethod("canonicalSecurityContextProvider");

            assertThat(canonicalProviderMethod.toGenericString()).contains("RoleScopeCollector");
        }

        private Method findMethod(String name) {
            return Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Method not found: " + name));
        }
    }

    @Nested
    @DisplayName("Post processor wiring")
    class PostProcessorWiring {

        @Test
        @DisplayName("Should require UnifiedVectorService for securityDecisionPostProcessor")
        void shouldRequireUnifiedVectorServiceForSecurityDecisionPostProcessor() throws Exception {
            Method method = CoreAutonomousAutoConfiguration.class
                    .getDeclaredMethod("securityDecisionPostProcessor", SecurityContextDataStore.class, UnifiedVectorService.class);

            assertThat(method.getReturnType()).isEqualTo(SecurityDecisionPostProcessor.class);
            ConditionalOnBean annotation = method.getAnnotation(ConditionalOnBean.class);
            assertThat(annotation).isNotNull();
            assertThat(annotation.value()).containsExactly(UnifiedVectorService.class);
        }
    }

}
