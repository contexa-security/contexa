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

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.core.validator.MfaPasskeyRegistrationPathValidator;
import io.contexa.contexaidentity.security.filter.MfaPendingAccessControlFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

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
                    .withBean(PlatformConfig.class, () -> Mockito.mock(PlatformConfig.class))
                    .withPropertyValues("contexa.identity.security-core.enabled=false")
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentitySecurityCoreAutoConfiguration.class);
                    });
        }

        @Test
        @DisplayName("Should limit Contexa-owned authentication handlers to CONTEXA_OWNED mode")
        void shouldLimitAuthenticationHandlersToContexaOwnedMode() {
            assertContexaOwnedCondition(IdentitySecurityCoreAutoConfiguration.class,
                    "primaryAuthenticationSuccessHandler");
            assertContexaOwnedCondition(IdentitySecurityCoreAutoConfiguration.class,
                    "unifiedAuthenticationFailureHandler");
            assertContexaOwnedCondition(IdentitySecurityCoreAutoConfiguration.class,
                    "mfaFactorProcessingSuccessHandler");

            ConditionalOnProperty handlerCondition = Arrays.stream(IdentityHandlerAutoConfiguration.class
                            .getAnnotationsByType(ConditionalOnProperty.class))
                    .filter(condition -> condition.prefix().equals("contexa.bridge"))
                    .findFirst()
                    .orElseThrow();
            assertContexaOwnedCondition(handlerCondition);
        }

        private void assertContexaOwnedCondition(Class<?> configurationClass, String methodName) {
            Method method = Arrays.stream(configurationClass.getDeclaredMethods())
                    .filter(candidate -> candidate.getName().equals(methodName))
                    .findFirst()
                    .orElseThrow();
            assertContexaOwnedCondition(method.getAnnotation(ConditionalOnProperty.class));
        }

        private void assertContexaOwnedCondition(ConditionalOnProperty condition) {
            assertThat(condition).isNotNull();
            assertThat(condition.prefix()).isEqualTo("contexa.bridge");
            assertThat(condition.name()).containsExactly("ownership");
            assertThat(condition.havingValue()).isEqualTo("CONTEXA_OWNED");
            assertThat(condition.matchIfMissing()).isFalse();
        }
    }

    @Nested
    @DisplayName("MFA pending access control")
    class MfaPendingAccessControl {

        @AfterEach
        void clearSecurityContext() {
            SecurityContextHolder.clearContext();
        }

        @Test
        @DisplayName("Filter and configurer beans are replaceable")
        void beansAreReplaceable() {
            Method filterMethod = findMethod("mfaPendingAccessControlFilter");
            Method configurerMethod = findMethod("mfaPendingAccessControlConfigurer");

            assertThat(filterMethod.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
            assertThat(configurerMethod.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
            ConditionalOnBean configurerCondition = configurerMethod.getAnnotation(ConditionalOnBean.class);
            assertThat(configurerCondition).isNotNull();
            assertThat(configurerCondition.value()).containsExactly(MfaPendingAccessControlFilter.class);
        }

        @Test
        @DisplayName("Servlet container registration of the filter is disabled")
        void servletRegistrationIsDisabled() {
            MfaPendingAccessControlFilter filter = Mockito.mock(MfaPendingAccessControlFilter.class);

            FilterRegistrationBean<MfaPendingAccessControlFilter> registration =
                    new IdentitySecurityCoreAutoConfiguration().mfaPendingAccessControlFilterRegistrationBean(filter);

            assertThat(registration.getFilter()).isSameAs(filter);
            assertThat(registration.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("Configured server error path stays reachable while MFA is pending")
        void configuredErrorPathIsPermitted() throws Exception {
            AuthContextProperties properties = new AuthContextProperties();
            MockEnvironment environment = new MockEnvironment().withProperty("server.error.path", "/failure-page");
            MfaPendingAccessControlFilter filter = new IdentitySecurityCoreAutoConfiguration()
                    .mfaPendingAccessControlFilter(
                            new AuthUrlProvider(properties),
                            new MfaFlowUrlRegistry(properties),
                            Mockito.mock(MfaSessionRepository.class),
                            Mockito.mock(AuthResponseWriter.class),
                            environment);
            SecurityContextHolder.setContext(new SecurityContextImpl(
                    UsernamePasswordAuthenticationToken.authenticated("user", null, List.of())));

            MockHttpServletRequest errorRequest = new MockHttpServletRequest("GET", "/failure-page");
            MfaPendingSessionMarker.mark(errorRequest, "mfa");
            MockFilterChain errorChain = new MockFilterChain();
            filter.doFilter(errorRequest, new MockHttpServletResponse(), errorChain);

            MockHttpServletRequest defaultErrorRequest = new MockHttpServletRequest("GET", "/error");
            MfaPendingSessionMarker.mark(defaultErrorRequest, "mfa");
            MockFilterChain defaultErrorChain = new MockFilterChain();
            filter.doFilter(defaultErrorRequest, new MockHttpServletResponse(), defaultErrorChain);

            assertThat(errorChain.getRequest()).isSameAs(errorRequest);
            assertThat(defaultErrorChain.getRequest()).isNull();
        }

        private Method findMethod(String methodName) {
            return Arrays.stream(IdentitySecurityCoreAutoConfiguration.class.getDeclaredMethods())
                    .filter(candidate -> candidate.getName().equals(methodName))
                    .findFirst()
                    .orElseThrow();
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

    @Nested
    @DisplayName("DSL validation")
    class DslValidation {

        @Test
        @DisplayName("Passkey registration path validator is registered as a replaceable flow validator")
        void passkeyRegistrationPathValidatorIsReplaceable() {
            Method method = Arrays.stream(IdentitySecurityCoreAutoConfiguration.class.getDeclaredMethods())
                    .filter(candidate -> candidate.getName().equals("mfaPasskeyRegistrationPathValidator"))
                    .findFirst()
                    .orElseThrow();

            assertThat(method.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
            assertThat(new IdentitySecurityCoreAutoConfiguration().mfaPasskeyRegistrationPathValidator())
                    .isInstanceOf(MfaPasskeyRegistrationPathValidator.class);
        }
    }
}
