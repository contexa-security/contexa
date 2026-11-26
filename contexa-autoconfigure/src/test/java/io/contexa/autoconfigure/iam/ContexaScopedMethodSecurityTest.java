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
package io.contexa.autoconfigure.iam;

import com.legacyshop.security.LegacySecurityApplication;
import io.contexa.autoconfigure.core.ContexaProxyModeAutoConfiguration;
import io.contexa.autoconfigure.iam.sample.ContexaSecuredSample;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandlerFactory;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * In every way of running Contexa it guards its own classes with {@code @PreAuthorize}; the application's annotations of the same kind stay as
 * dormant as the application left them, and an application that turned method security on itself keeps its own handler for its own
 * annotations.
 */
class ContexaScopedMethodSecurityTest {

    private ApplicationContextRunner runner(Class<?> application) {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED")
                .withUserConfiguration(application, ContexaSecuredSample.Definition.class, HandlerFactory.class)
                .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, ContexaProxyModeAutoConfiguration.class,
                        IamSecurityAutoConfiguration.ContexaScopedMethodSecurityConfiguration.class));
    }

    private ApplicationContextRunner runner(Class<?> application, String mode, String ownership) {
        return new ApplicationContextRunner()
                .withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode, ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership)
                .withUserConfiguration(application, ContexaSecuredSample.Definition.class, HandlerFactory.class)
                .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, ContexaProxyModeAutoConfiguration.class,
                        IamSecurityAutoConfiguration.ContexaScopedMethodSecurityConfiguration.class));
    }

    /** M4 of docs/agent/운영모드-정상화-구현계획.md: Contexa's classes are guarded in every way of running Contexa, and only they are. */
    @ParameterizedTest(name = "{0} + {1}")
    @CsvSource({"SANDBOX, HOST_OWNED", "SANDBOX, CONTEXA_OWNED", "FULL, HOST_OWNED", "FULL, CONTEXA_OWNED"})
    @DisplayName("어느 조합이든 Contexa 클래스의 @PreAuthorize만 집행하고 앱의 잠든 @PreAuthorize는 그대로 둔다")
    void contexasOwnClassesAreGuardedInEveryWayOfRunningAndTheApplicationsAreNot(String mode, String ownership) {
        runner(LegacySecurityApplication.Dormant.class, mode, ownership).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("contexaPreAuthorizeAdvisor");
            ContexaSecuredSample sample = context.getBean(ContexaSecuredSample.class);

            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "x", "ROLE_USER"));
            assertThatThrownBy(sample::adminOnly).as("Contexa's class, a user without the role").isInstanceOf(AuthorizationDeniedException.class);
            assertThat(context.getBean(LegacySecurityApplication.AppService.class).locked())
                    .as("the application's @PreAuthorize(\"denyAll()\") stays as dormant as the application left it").isEqualTo("reached");
            assertThat(context.getBeansOfType(MethodSecurityExpressionHandler.class))
                    .as("no application-wide MethodSecurityExpressionHandler appears because of Contexa").isEmpty();
        });
    }

    /** With prePostEnabled the application's interceptor evaluates Contexa's annotations too; a second evaluation only repeats it. */
    @Test
    void legacyMethodSecurityThatReadsPreAuthorizeIsNotDoubled() {
        assertThat(ContexaScopedMethodSecurity.servesPrePostTheLegacyWay(beansWith(LegacyPrePost.class))).isTrue();
    }

    /** securedEnabled alone reads no @PreAuthorize: Contexa's own would stand unguarded if the advisor stepped back. */
    @Test
    void legacyMethodSecurityThatDoesNotReadPreAuthorizeLeavesContexasOwnGuarded() {
        assertThat(ContexaScopedMethodSecurity.servesPrePostTheLegacyWay(beansWith(LegacySecuredOnly.class))).isFalse();
        assertThat(ContexaScopedMethodSecurity.servesPrePostTheLegacyWay(beansWith(Object.class))).isFalse();
    }

    private static DefaultListableBeanFactory beansWith(Class<?> application) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerBeanDefinition("application", new RootBeanDefinition(application));
        return beans;
    }

    @SuppressWarnings("deprecation")
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    static class LegacyPrePost {
    }

    @SuppressWarnings("deprecation")
    @EnableGlobalMethodSecurity(securedEnabled = true)
    static class LegacySecuredOnly {
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void theApplicationsDormantPreAuthorizeStaysDormant() {
        runner(LegacySecurityApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBean(LegacySecurityApplication.AppService.class).locked())
                    .as("the application never turned method security on: its @PreAuthorize(\"denyAll()\") is not enforced")
                    .isEqualTo("reached");
        });
    }

    @Test
    void contexasOwnPreAuthorizeIsEnforced() {
        runner(LegacySecurityApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSecuredSample sample = context.getBean(ContexaSecuredSample.class);

            assertThatThrownBy(sample::locked).as("nobody signed in: the interceptor asks for an authentication")
                    .isInstanceOf(AuthenticationCredentialsNotFoundException.class);

            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "x", "ROLE_USER"));
            assertThatThrownBy(sample::locked).as("denyAll()").isInstanceOf(AuthorizationDeniedException.class);
            assertThatThrownBy(sample::adminOnly).as("a user without the role").isInstanceOf(AuthorizationDeniedException.class);

            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("admin", "x", "ROLE_ADMIN"));
            assertThat(sample.adminOnly()).as("an administrator").isEqualTo("admin");
        });
    }

    @Test
    void contexasHandlerIsNotPublishedToTheApplication() {
        runner(LegacySecurityApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBeansOfType(MethodSecurityExpressionHandler.class))
                    .as("no application-wide MethodSecurityExpressionHandler appears because of Contexa").isEmpty();
        });
    }

    @Test
    void anApplicationThatTurnedMethodSecurityOnItselfIsGivenNoSecondInterceptor() {
        runner(LegacySecurityApplication.Enabled.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean("contexaPreAuthorizeAdvisor", PointcutAdvisor.class).getPointcut().getClassFilter()
                    .matches(ContexaSecuredSample.class)).as("Contexa's advisor leaves its classes to the application's interceptor").isFalse();
            assertThat(context.getBeansOfType(MethodSecurityExpressionHandler.class))
                    .as("the application keeps Spring Security's own handler for its own annotations").isEmpty();

            assertThatThrownBy(() -> context.getBean(LegacySecurityApplication.AppService.class).locked())
                    .as("the application asked for it").isInstanceOf(AuthorizationDeniedException.class);
            assertThatThrownBy(() -> context.getBean(ContexaSecuredSample.class).locked())
                    .as("Contexa's annotation is served by the application's interceptor").isInstanceOf(AuthorizationDeniedException.class);
        });
    }

    /** Comes after Contexa's configuration and switches method security on, as a library's auto-configuration might. */
    @AutoConfiguration(after = IamSecurityAutoConfiguration.ContexaScopedMethodSecurityConfiguration.class)
    @EnableMethodSecurity
    static class LaterMethodSecurity {
    }

    @Test
    void contexasAdvisorCoversContexasClassesAndNotTheApplicationsWhenNothingElseIsOn() {
        runner(LegacySecurityApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            PointcutAdvisor advisor = context.getBean("contexaPreAuthorizeAdvisor", PointcutAdvisor.class);

            assertThat(advisor.getPointcut().getClassFilter().matches(ContexaSecuredSample.class)).isTrue();
            assertThat(advisor.getPointcut().getClassFilter().matches(LegacySecurityApplication.AppService.class)).isFalse();
        });
    }

    @Test
    void methodSecuritySwitchedOnLaterByAnotherAutoConfigurationTakesOverContexasClasses() {
        runner(LegacySecurityApplication.Dormant.class)
                .withConfiguration(AutoConfigurations.of(LaterMethodSecurity.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).as("Contexa's was evaluated first and is there").hasBean("contexaPreAuthorizeAdvisor");
                    assertThat(context).as("and so is the one that came after").hasBean("preAuthorizeAuthorizationMethodInterceptor");
                    PointcutAdvisor advisor = context.getBean("contexaPreAuthorizeAdvisor", PointcutAdvisor.class);

                    assertThat(advisor.getPointcut().getClassFilter().matches(ContexaSecuredSample.class))
                            .as("Contexa's advisor leaves its classes to the interceptor that came after").isFalse();
                    assertThatThrownBy(() -> context.getBean(ContexaSecuredSample.class).locked())
                            .isInstanceOf(AuthorizationDeniedException.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class HandlerFactory {

        @Bean
        CustomMethodSecurityExpressionHandlerFactory customMethodSecurityExpressionHandlerFactory() {
            return new CustomMethodSecurityExpressionHandlerFactory(
                    new SecurityZeroTrustProperties(),
                    mock(CompositePermissionEvaluator.class),
                    authorities -> new ArrayList<>(authorities),
                    mock(PolicyRetrievalPoint.class),
                    mock(ContextHandler.class),
                    mock(AuditLogRepository.class),
                    mock(ZeroTrustActionRepository.class),
                    new PolicyCombiningProperties());
        }
    }
}
