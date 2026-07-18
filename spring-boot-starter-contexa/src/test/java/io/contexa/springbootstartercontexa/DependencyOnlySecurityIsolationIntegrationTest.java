/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.bootstrap.SecurityPlatformInitializer;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.sql.init.SqlInitializationAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.core.session.SessionRegistry;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class DependencyOnlySecurityIsolationIntegrationTest {

    private static final List<Class<?>> SECURITY_BEAN_TYPES = List.of(
            SecurityFilterChain.class,
            AuthenticationProvider.class,
            AuthenticationManager.class,
            AuthenticationEntryPoint.class,
            AuthenticationSuccessHandler.class,
            AuthenticationFailureHandler.class,
            LogoutHandler.class,
            LogoutSuccessHandler.class,
            RememberMeServices.class,
            SessionAuthenticationStrategy.class,
            SessionRegistry.class,
            SecurityContextRepository.class,
            SecurityContextHolderStrategy.class);

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withUserConfiguration(DependencyOnlyApplication.class);

    @Test
    void dependencyOnlyKeepsBootDefaultSecurityChainWithoutContexaFilters() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(SecurityFilterChain.class);
            assertThat(context).doesNotHaveBean("securityFilterChain");
            assertThat(context).doesNotHaveBean(IdentitySecurityCoreAutoConfiguration.class);
            assertThat(context).doesNotHaveBean(SecurityPlatformInitializer.class);
            assertThat(context).doesNotHaveBean(BridgeResolutionFilter.class);

            SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
            assertNoContexaFilters(chain);
        });
    }

    @Test
    void dependencyOnlyPreservesHostSecurityChainAsTheOnlyChain() {
        contextRunner.withUserConfiguration(HostSecurityConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    Map<String, SecurityFilterChain> chains = context.getBeansOfType(SecurityFilterChain.class);
                    SecurityFilterChain hostChain = context.getBean(
                            "hostSecurityFilterChain", SecurityFilterChain.class);

                    assertThat(chains).containsOnlyKeys("hostSecurityFilterChain");
                    assertThat(chains.get("hostSecurityFilterChain")).isSameAs(hostChain);
                    assertThat(context.getBean(FilterChainProxy.class).getFilterChains())
                            .containsExactly(hostChain);
                    assertNoContexaFilters(hostChain);
                });
    }

    @Test
    void dependencyOnlySecurityBeanGraphMatchesStarterAbsentBootBaseline() {
        SecurityBeanGraph baseline = captureBaseline(contexaDisabledBaselineRunner());

        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            SecurityBeanGraph actual = securityBeanGraph(context);
            assertThat(actual).isEqualTo(baseline);
            assertThat(actual.toString()).doesNotContain("|CONTEXA");
        });
    }

    @Test
    void dependencyOnlyHostSecurityBeanGraphMatchesStarterAbsentHostBaseline() {
        SecurityBeanGraph baseline = captureBaseline(
                contexaDisabledBaselineRunner().withUserConfiguration(HostSecurityConfiguration.class));

        contextRunner.withUserConfiguration(HostSecurityConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    SecurityBeanGraph actual = securityBeanGraph(context);
                    assertThat(actual).isEqualTo(baseline);
                    assertThat(actual.toString()).doesNotContain("|CONTEXA");
                });
    }

    private WebApplicationContextRunner contexaDisabledBaselineRunner() {
        return new WebApplicationContextRunner()
                .withPropertyValues(
                        "contexa.enabled=false",
                        "contexa.enterprise.enabled=false")
                .withUserConfiguration(DependencyOnlyApplication.class);
    }

    private SecurityBeanGraph captureBaseline(WebApplicationContextRunner runner) {
        AtomicReference<SecurityBeanGraph> baseline = new AtomicReference<>();
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            baseline.set(securityBeanGraph(context));
        });
        assertThat(baseline.get()).isNotNull();
        return baseline.get();
    }

    private SecurityBeanGraph securityBeanGraph(ConfigurableApplicationContext context) {
        Map<String, List<String>> categories = new LinkedHashMap<>();
        for (Class<?> beanType : SECURITY_BEAN_TYPES) {
            List<String> signatures = context.getBeansOfType(beanType).entrySet().stream()
                    .map(entry -> beanSignature(entry.getKey(), entry.getValue()))
                    .sorted()
                    .toList();
            categories.put(beanType.getName(), signatures);
        }
        return new SecurityBeanGraph(Map.copyOf(categories));
    }

    private String beanSignature(String beanName, Object bean) {
        int order = bean instanceof Ordered ordered ? ordered.getOrder() : Ordered.LOWEST_PRECEDENCE;
        String owner = bean.getClass().getName().startsWith("io.contexa.")
                ? "CONTEXA"
                : "HOST_OR_BOOT";
        return beanName + "|" + bean.getClass().getName() + "|" + order + "|" + owner;
    }

    private void assertNoContexaFilters(SecurityFilterChain chain) {
        assertThat(chain.getFilters())
                .extracting(Filter::getClass)
                .extracting(Class::getName)
                .noneMatch(name -> name.startsWith("io.contexa."));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration(exclude = {
            DataSourceAutoConfiguration.class,
            DataSourceTransactionManagerAutoConfiguration.class,
            HibernateJpaAutoConfiguration.class,
            SqlInitializationAutoConfiguration.class
    })
    static class DependencyOnlyApplication {
    }

    @Configuration(proxyBeanMethods = false)
    static class HostSecurityConfiguration {

        @Bean
        SecurityFilterChain hostSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
            return httpSecurity
                    .securityMatcher("/host/**")
                    .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                    .httpBasic(Customizer.withDefaults())
                    .build();
        }
    }

    private record SecurityBeanGraph(Map<String, List<String>> categories) {
    }
}
