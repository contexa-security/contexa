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
package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcOperations;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the conditional activation gates of IdentitySecurityCoreAutoConfiguration.
 * Full bean creation tests are omitted due to deep dependency chains.
 */
@DisplayName("IdentitySecurityCoreAutoConfiguration")
class IdentitySecurityCoreAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdentitySecurityCoreAutoConfiguration.class));

    @Nested
    @DisplayName("Activation gates")
    class ActivationGates {

        @Test
        @DisplayName("Should not activate without PlatformConfig bean")
        void shouldNotActivateWithoutPlatformConfig() {
            contextRunner
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentitySecurityCoreAutoConfiguration.class);
                    });
        }

        @Test
        @DisplayName("Should not activate when contexa.identity.security-core.enabled=false")
        void shouldNotActivateWhenDisabled() {
            contextRunner
                    .withBean(PlatformConfig.class, () -> org.mockito.Mockito.mock(PlatformConfig.class))
                    .withPropertyValues("contexa.identity.security-core.enabled=false")
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentitySecurityCoreAutoConfiguration.class);
                    });
        }
    }

    @Nested
    @DisplayName("Contexa datasource isolation")
    class ContexaDatasourceIsolation {

        @Test
        @DisplayName("Should bind WebAuthn repositories to contexaJdbcTemplate")
        void shouldBindWebAuthnRepositoriesToContexaJdbcTemplate() throws Exception {
            assertContexaJdbcTemplateBinding(IdentitySecurityCoreAutoConfiguration.class,
                    "publicKeyCredentialUserEntityRepository");
            assertContexaJdbcTemplateBinding(IdentitySecurityCoreAutoConfiguration.class,
                    "userCredentialRepository");
            assertContexaJdbcTemplateBinding(IdentityWebAuthnAutoConfiguration.class,
                    "publicKeyCredentialUserEntityRepository");
            assertContexaJdbcTemplateBinding(IdentityWebAuthnAutoConfiguration.class,
                    "userCredentialRepository");
        }

        private void assertContexaJdbcTemplateBinding(Class<?> configurationClass, String methodName) throws Exception {
            Method method = configurationClass.getMethod(methodName, JdbcOperations.class);
            ConditionalOnBean conditionalOnBean = method.getAnnotation(ConditionalOnBean.class);
            Parameter parameter = method.getParameters()[0];
            Qualifier qualifier = parameter.getAnnotation(Qualifier.class);

            assertThat(conditionalOnBean).isNotNull();
            assertThat(conditionalOnBean.name()).contains("contexaJdbcTemplate");
            assertThat(qualifier).isNotNull();
            assertThat(qualifier.value()).isEqualTo("contexaJdbcTemplate");
        }
    }
}
