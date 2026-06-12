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
package io.contexa.autoconfigure.core.hcad;

import static org.assertj.core.api.Assertions.assertThat;
import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

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
            // All contexa.* keys live under the "contexa" prefix (mirrors yml convention
            // contexa.hcad.geoip.enabled / contexa.hcad.pre-trigger.enabled etc.).
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
                    ConditionalOnBean.class))
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
