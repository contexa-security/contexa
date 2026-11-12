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
package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexaidentity.security.handler.MfaFactorProcessingSuccessHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationFailureHandler;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityFilterChainRegistrarTest {

    @Mock
    private ConfiguredFactorFilterProvider configuredFactorFilterProvider;

    @Mock
    private ConfigurableApplicationContext applicationContext;

    @Mock
    private DefaultListableBeanFactory beanFactory;

    private Map<String, Class<? extends Filter>> stepFilterClasses;
    private SecurityFilterChainRegistrar registrar;

    @BeforeEach
    void setUp() {
        stepFilterClasses = new HashMap<>();
        registrar = new SecurityFilterChainRegistrar(configuredFactorFilterProvider, stepFilterClasses);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
    }

    @Nested
    @DisplayName("Constructor validation tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with null ConfiguredFactorFilterProvider should throw")
        void constructorWithNullProviderThrows() {
            assertThatThrownBy(() -> new SecurityFilterChainRegistrar(null, stepFilterClasses))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("ConfiguredFactorFilterProvider cannot be null");
        }

        @Test
        @DisplayName("Constructor with null stepFilterClasses should throw")
        void constructorWithNullStepFilterClassesThrows() {
            assertThatThrownBy(() -> new SecurityFilterChainRegistrar(configuredFactorFilterProvider, null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("stepFilterClasses cannot be null");
        }
    }

    @Nested
    @DisplayName("SecurityFilterChain bean registration tests")
    class BeanRegistrationTests {

        @Test
        @DisplayName("registerSecurityFilterChains should throw when flows list is null")
        void registerWithNullFlowsThrows() {
            assertThatThrownBy(() -> registrar.registerSecurityFilterChains(null, applicationContext))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("registerSecurityFilterChains should throw when context is null")
        void registerWithNullContextThrows() {
            assertThatThrownBy(() -> registrar.registerSecurityFilterChains(List.of(), null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("registerSecurityFilterChains with non-configurable context should return gracefully")
        void registerWithNonConfigurableContextReturns() {
            ApplicationContext plainContext = mock(ApplicationContext.class);

            // Should not throw - just logs and returns
            assertThatCode(() -> registrar.registerSecurityFilterChains(List.of(), plainContext))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("registerSecurityFilterChains should register bean for each flow")
        void registerCreatesBeansForFlows() throws Exception {
            FlowContext fc = createMockFlowContext("FORM", 0, List.of());
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, Collections.emptyList());
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(Collections.emptyList());

            registrar.registerSecurityFilterChains(List.of(fc), applicationContext);

            verify(beanFactory).registerBeanDefinition(
                    eq("contexaFORMSecurityFilterChain1"),
                    any(BeanDefinition.class));
        }
    }

    @Nested
    @DisplayName("Filter registration order tests")
    class FilterRegistrationOrderTests {

        @Test
        @DisplayName("buildAndRegisterFilters should register filters in ConfiguredFactorFilterProvider")
        void buildRegistersFiltersInProvider() throws Exception {
            Filter mockFilter = mock(Filter.class);
            stepFilterClasses.put("ott", mockFilter.getClass());

            AuthenticationStepConfig ottStep = new AuthenticationStepConfig();
            ottStep.setStepId("mfa:ott:1");
            ottStep.setType("ott");

            FlowContext fc = createMockFlowContext("FORM", 0, List.of(ottStep));
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, List.of(mockFilter));
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(List.of(ottStep));

            OrderedSecurityFilterChain result = registrar.buildAndRegisterFilters(fc, applicationContext);

            assertThat(result).isNotNull();
            verify(configuredFactorFilterProvider).registerFilter(
                    eq(FactorIdentifier.of("FORM", "mfa:ott:1")),
                    eq(mockFilter));
        }

        @Test
        @DisplayName("MFA flow should skip primary step (order 0) during filter registration")
        void mfaFlowSkipsPrimaryStep() throws Exception {
            Filter secondaryFilter = mock(Filter.class);
            stepFilterClasses.put("ott", secondaryFilter.getClass());

            AuthenticationStepConfig primaryStep = new AuthenticationStepConfig();
            primaryStep.setStepId("mfa:form:0");
            primaryStep.setType("form");
            primaryStep.setOrder(0);

            AuthenticationStepConfig secondaryStep = new AuthenticationStepConfig();
            secondaryStep.setStepId("mfa:ott:1");
            secondaryStep.setType("ott");
            secondaryStep.setOrder(1);

            FlowContext fc = createMockFlowContext("MFA", 0, List.of(primaryStep, secondaryStep));
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, List.of(secondaryFilter));
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(List.of(primaryStep, secondaryStep));

            OrderedSecurityFilterChain result = registrar.buildAndRegisterFilters(fc, applicationContext);

            assertThat(result).isNotNull();
            // Primary step (order 0) should NOT be registered
            verify(configuredFactorFilterProvider, never()).registerFilter(
                    eq(FactorIdentifier.of("MFA", "mfa:form:0")), any());
            // Secondary step should be registered
            verify(configuredFactorFilterProvider).registerFilter(
                    eq(FactorIdentifier.of("MFA", "mfa:ott:1")),
                    eq(secondaryFilter));
        }

        @Test
        @DisplayName("Step without stepId should be skipped with error log")
        void stepWithoutStepIdIsSkipped() throws Exception {
            AuthenticationStepConfig stepWithoutId = new AuthenticationStepConfig();
            stepWithoutId.setType("ott");
            // stepId is not set

            FlowContext fc = createMockFlowContext("FORM", 0, List.of(stepWithoutId));
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, Collections.emptyList());
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(List.of(stepWithoutId));

            OrderedSecurityFilterChain result = registrar.buildAndRegisterFilters(fc, applicationContext);

            assertThat(result).isNotNull();
            // Should not attempt to register filter for step without id
            verify(configuredFactorFilterProvider, never()).registerFilter(any(), any());
        }

        @Test
        @DisplayName("Step with unconfigured filter class should throw IllegalStateException")
        void unconfiguredFilterClassThrows() throws Exception {
            AuthenticationStepConfig step = new AuthenticationStepConfig();
            step.setStepId("form:unknown:1");
            step.setType("unknown");

            FlowContext fc = createMockFlowContext("FORM", 0, List.of(step));
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, Collections.emptyList());
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(List.of(step));

            // stepFilterClasses does not contain "unknown" type
            assertThatThrownBy(() -> registrar.buildAndRegisterFilters(fc, applicationContext))
                    .isInstanceOf(RuntimeException.class)
                    .hasCauseInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("buildAndRegisterFilters should preserve the order of filters returned from HttpSecurity")
        void buildPreservesFilterOrder() throws Exception {
            Filter firstFilter = mock(Filter.class);
            Filter secondFilter = mock(Filter.class);

            FlowContext fc = createMockFlowContext("FORM", 10, List.of());
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, List.of(firstFilter, secondFilter));
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(Collections.emptyList());

            OrderedSecurityFilterChain result = registrar.buildAndRegisterFilters(fc, applicationContext);

            assertThat(result).isNotNull();
            // the chain's own filters, in their order, between the two that open and close Contexa's work
            List<Filter> filters = result.getFilters();
            assertThat(filters.subList(1, filters.size() - 1)).containsExactly(firstFilter, secondFilter);
            assertThat(result.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 10);
        }
    }

    @Nested
    @DisplayName("Contexa's work in its own chain (PR-201)")
    class ContexaWorkTests {

        private final List<String> seen = new ArrayList<>();

        @Test
        @DisplayName("The chain's filters run as Contexa's work and the application behind them does not")
        void theChainsFiltersRunAsContexasWork() throws Exception {
            OrderedSecurityFilterChain chain = chainOf(marks("first"), marks("last"));

            new FilterChainProxy(chain).doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse(),
                    (request, response) -> seen.add("application " + RequestPathScope.inContexaWork()));

            assertThat(seen).containsExactly("first true", "last true", "application false", "last true", "first true");
            assertThat(RequestPathScope.inContexaWork()).isFalse();
        }

        @Test
        @DisplayName("A protected call of the application keeps its own marks inside the chain's")
        void aProtectedCallInsideTheApplication() throws Exception {
            OrderedSecurityFilterChain chain = chainOf(marks("filter"));

            new FilterChainProxy(chain).doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse(),
                    (request, response) -> {
                        RequestPathScope.enter();
                        seen.add("call " + RequestPathScope.inContexaWork());
                        int work = RequestPathScope.suspend();
                        seen.add("method " + RequestPathScope.inContexaWork());
                        RequestPathScope.resume(work);
                        RequestPathScope.leave();
                        seen.add("application " + RequestPathScope.inContexaWork());
                    });

            assertThat(seen).containsExactly("filter true", "call true", "method false", "application false",
                    "filter true");
            assertThat(RequestPathScope.inContexaWork()).isFalse();
        }

        @Test
        @DisplayName("The application's failure comes back through the chain as Contexa's work and leaves no mark")
        void theApplicationsFailureLeavesNoMark() throws Exception {
            OrderedSecurityFilterChain chain = chainOf(marks("filter"));

            assertThatThrownBy(() -> new FilterChainProxy(chain).doFilter(new MockHttpServletRequest("GET", "/"),
                    new MockHttpServletResponse(), (request, response) -> {
                        throw new ServletException("the application failed");
                    })).isInstanceOf(ServletException.class);

            assertThat(seen).containsExactly("filter true", "filter true");
            assertThat(RequestPathScope.inContexaWork()).isFalse();
        }

        @Test
        @DisplayName("A filter of the chain that fails leaves no mark")
        void aFailingFilterLeavesNoMark() throws Exception {
            OrderedSecurityFilterChain chain = chainOf((request, response, next) -> {
                throw new IllegalStateException("the store did not answer");
            });

            assertThatThrownBy(() -> new FilterChainProxy(chain).doFilter(new MockHttpServletRequest("GET", "/"),
                    new MockHttpServletResponse(), (request, response) -> seen.add("application")))
                    .isInstanceOf(IllegalStateException.class);

            assertThat(seen).isEmpty();
            assertThat(RequestPathScope.inContexaWork()).isFalse();
        }

        private OrderedSecurityFilterChain chainOf(Filter... filters) throws Exception {
            FlowContext fc = createMockFlowContext("FORM", 10, List.of());
            when(fc.http().build()).thenReturn(new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of(filters)));
            return registrar.buildAndRegisterFilters(fc, applicationContext);
        }

        /** A filter that writes down, on the way in and on the way out, whether it runs as Contexa's work. */
        private Filter marks(String name) {
            return (request, response, next) -> {
                seen.add(name + " " + RequestPathScope.inContexaWork());
                try {
                    next.doFilter(request, response);
                } finally {
                    seen.add(name + " " + RequestPathScope.inContexaWork());
                }
            };
        }
    }

    @Nested
    @DisplayName("WebAuthn handler replacement tests")
    class WebAuthnHandlerReplacementTests {

        @Test
        @DisplayName("Non-passkey flow should not attempt handler replacement")
        void nonPasskeyFlowSkipsReplacement() throws Exception {
            AuthenticationStepConfig formStep = new AuthenticationStepConfig();
            formStep.setStepId("form:form:0");
            formStep.setType("form");
            stepFilterClasses.put("form", Filter.class);

            Filter formFilter = mock(Filter.class);

            FlowContext fc = createMockFlowContext("FORM", 0, List.of(formStep));
            DefaultSecurityFilterChain builtChain = new DefaultSecurityFilterChain(
                    AnyRequestMatcher.INSTANCE, List.of(formFilter));
            when(fc.http().build()).thenReturn(builtChain);

            AuthenticationFlowConfig flowConfig = fc.flow();
            when(flowConfig.getStepConfigs()).thenReturn(List.of(formStep));

            OrderedSecurityFilterChain result = registrar.buildAndRegisterFilters(fc, applicationContext);

            assertThat(result).isNotNull();
            // No AuthContextProperties lookup for handler replacement
            verify(applicationContext, never()).getBean(AuthContextProperties.class);
        }
    }

    @Nested
    @DisplayName("Unreachable flow report (A1-10)")
    class UnreachableFlowTests {

        private final RequestMatcher tokenRequests = request -> request.getHeader("Authorization") != null;

        @Test
        @DisplayName("A flow after one that takes every request is reported")
        void flowAfterAnyRequestFlowIsReported() {
            List<String> problems = SecurityFilterChainRegistrar.unreachableFlows(List.of(
                    new SecurityFilterChainRegistrar.BuiltFlow("mfa", 200, AnyRequestMatcher.INSTANCE),
                    new SecurityFilterChainRegistrar.BuiltFlow("rest_flow", 200, tokenRequests)));

            assertThat(problems).singleElement().asString()
                    .contains("'rest_flow' is never reached", "'mfa'", "TOKEN_REQUESTS");
        }

        @Test
        @DisplayName("A token-scoped flow ordered before the session flow is not reported")
        void tokenScopedFlowFirstIsFine() {
            assertThat(SecurityFilterChainRegistrar.unreachableFlows(List.of(
                    new SecurityFilterChainRegistrar.BuiltFlow("mfa", 200, AnyRequestMatcher.INSTANCE),
                    new SecurityFilterChainRegistrar.BuiltFlow("rest_flow", 150, tokenRequests)))).isEmpty();
            assertThat(SecurityFilterChainRegistrar.unreachableFlows(List.of(
                    new SecurityFilterChainRegistrar.BuiltFlow("mfa", 200, AnyRequestMatcher.INSTANCE)))).isEmpty();
        }

        @Test
        @DisplayName("registerSecurityFilterChains reports nothing for a single flow")
        void registrationWithOneFlowStillRegisters() throws Exception {
            FlowContext fc = createMockFlowContext("FORM", 0, List.of());
            when(fc.http().build()).thenReturn(new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of()));

            registrar.registerSecurityFilterChains(List.of(fc), applicationContext);

            verify(beanFactory).registerBeanDefinition(eq("contexaFORMSecurityFilterChain1"), any(BeanDefinition.class));
        }
    }

    // -- helper methods --

    private FlowContext createMockFlowContext(String typeName, int order,
                                              List<AuthenticationStepConfig> steps) {
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        when(flowConfig.getTypeName()).thenReturn(typeName);
        when(flowConfig.getOrder()).thenReturn(order);
        when(flowConfig.getStepConfigs()).thenReturn(steps);

        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        PlatformContext platformContext = mock(PlatformContext.class);
        PlatformConfig platformConfig = mock(PlatformConfig.class);

        return new FlowContext(flowConfig, httpSecurity, platformContext, platformConfig);
    }
}
