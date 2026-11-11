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
package io.contexa.autoconfigure.ai;

import io.contexa.autoconfigure.identity.IdentitySecurityCoreContexaOwnedConfiguration;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.AnnotatedGenericBeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.web.filter.ServletRequestPathFilter;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The refusal of an application chain made from the bean definitions: it refuses only what the later refusal refuses for
 * certain, and leaves everything else to it.
 */
class ContexaOwnedChainDefinitionCheckTest {

    private static final String WEB_SECURITY = WebSecurityConfiguration.class.getName();
    private static final String PROXY = "springSecurityFilterChain";

    // ---- what a chain method returns, read from its byte code

    @Test
    void whatHttpSecurityBuildsIsCertain() throws Exception {
        for (String method : List.of("fluent", "statementByStatement", "declaresTheDefaultChain", "withOtherParameters",
                "staticMethod", "throwsWhenItCannotBuild")) {
            assertThat(certain(Chains.class, method)).as(method).isTrue();
        }
    }

    @Test
    void whatMayBeAnotherChainIsNotCertain() throws Exception {
        for (String method : List.of("onACondition", "nullOnACondition", "throughALocal", "throughAHelper", "withoutHttpSecurity",
                "fromAProvider", "fromAField", "aFallbackOnFailure", "withAFinallyBlock", "declaresContexasChain",
                "declaresAnything", "overloaded", "madeByHand")) {
            assertThat(certain(Chains.class, method)).as(method).isFalse();
        }
    }

    /** Spring calls the override of the class that declares the bean, so the method of its superclass says nothing. */
    @Test
    void anOverriddenMethodIsNotCertain() throws Exception {
        assertThat(ContexaOwnedChainDefinitionCheck.returnsOnlyWhatHttpSecurityBuilds(OverridingChains.class,
                Chains.class.getName(), "fluent")).isFalse();
        assertThat(ContexaOwnedChainDefinitionCheck.returnsOnlyWhatHttpSecurityBuilds(InheritingChains.class,
                Chains.class.getName(), "fluent")).isTrue();
    }

    // ---- what the bean definitions say

    @Test
    void anApplicationChainBuiltByHttpSecurityIsRefused() throws Exception {
        DefaultListableBeanFactory beans = contexaOwned(true);
        chain(beans, "hostChain", "fluent");

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(beans)).containsExactly("hostChain");
    }

    @Test
    void contexasPlaceholderIsNotTheApplications() throws Exception {
        DefaultListableBeanFactory beans = contexaOwned(true);
        chain(beans, IdentitySecurityCoreContexaOwnedConfiguration.PLACEHOLDER_CHAIN, "fluent");

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(beans)).isEmpty();
    }

    /** The chain proxy is given the chains by injection: a chain that is no candidate for it is not refused later either. */
    @Test
    void aChainTheProxyIsNotGivenIsNotRefused() throws Exception {
        DefaultListableBeanFactory beans = contexaOwned(true);
        chain(beans, "notACandidate", "fluent").setAutowireCandidate(false);
        chain(beans, "notADefaultCandidate", "fluent").setDefaultCandidate(false);
        chain(beans, "abstractChain", "fluent").setAbstract(true);

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(beans)).isEmpty();
    }

    @Test
    void aChainThatMayHaveNoFilterIsLeftToTheLaterRefusal() throws Exception {
        DefaultListableBeanFactory beans = contexaOwned(true);
        chain(beans, "onACondition", "onACondition");
        beans.registerSingleton("registeredInCode", new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE));

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(beans)).isEmpty();
    }

    @Test
    void nothingIsRefusedWhenTheLaterRefusalIsNotContexas() throws Exception {
        DefaultListableBeanFactory replaced = contexaOwned(true);
        replaced.removeBeanDefinition(ContexaOwnedChainDefinitionCheck.LATER_REFUSAL);
        replaced.registerBeanDefinition(ContexaOwnedChainDefinitionCheck.LATER_REFUSAL,
                beanMethod(Chains.class, "fluent", "chains"));
        chain(replaced, "hostChain", "fluent");
        DefaultListableBeanFactory missing = contexaOwned(true);
        missing.removeBeanDefinition(ContexaOwnedChainDefinitionCheck.LATER_REFUSAL);
        chain(missing, "hostChain", "fluent");

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(replaced)).isEmpty();
        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(missing)).isEmpty();
    }

    @Test
    void nothingIsRefusedWhenTheChainProxyIsNotSpringSecuritys() throws Exception {
        DefaultListableBeanFactory another = contexaOwned(true);
        another.removeBeanDefinition(PROXY);
        another.registerBeanDefinition(PROXY, new RootBeanDefinition(FilterChainProxy.class));
        chain(another, "hostChain", "fluent");
        DefaultListableBeanFactory none = contexaOwned(true);
        none.removeBeanDefinition(WEB_SECURITY);
        chain(none, "hostChain", "fluent");

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(another)).isEmpty();
        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(none)).isEmpty();
    }

    @Test
    void nothingIsRefusedWhenAnotherHttpSecurityCanBeInjected() throws Exception {
        DefaultListableBeanFactory beans = contexaOwned(true);
        beans.registerBeanDefinition("handMadeHttpSecurity", new RootBeanDefinition(HttpSecurity.class));
        chain(beans, "hostChain", "fluent");

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(beans)).isEmpty();
    }

    /** Without Spring Security's composite around the proxy, the debug filter would hide the chains from the later refusal. */
    @Test
    void withoutTheCompositeAnythingThatMaySwitchOnTheDebugFilterLeavesTheChainsToTheLaterRefusal() throws Exception {
        DefaultListableBeanFactory customized = contexaOwned(false);
        chain(customized, "hostChain", "fluent");
        customized.registerBeanDefinition("hostCustomizer", beanMethod(Customizers.class, "customizer", "customizers"));
        customized.registerBeanDefinition("customizers", new RootBeanDefinition(Customizers.class));
        DefaultListableBeanFactory debugged = contexaOwned(false);
        chain(debugged, "hostChain", "fluent");
        debugged.registerBeanDefinition("debugged", new AnnotatedGenericBeanDefinition(DebuggedSecurity.class));
        DefaultListableBeanFactory plain = contexaOwned(false);
        chain(plain, "hostChain", "fluent");
        DefaultListableBeanFactory wrapped = contexaOwned(true);
        chain(wrapped, "hostChain", "fluent");
        wrapped.registerBeanDefinition("hostCustomizer", beanMethod(Customizers.class, "customizer", "customizers"));
        wrapped.registerBeanDefinition("customizers", new RootBeanDefinition(Customizers.class));

        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(customized)).isEmpty();
        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(debugged)).isEmpty();
        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(plain)).containsExactly("hostChain");
        assertThat(ContexaOwnedChainDefinitionCheck.certainApplicationChains(wrapped)).containsExactly("hostChain");
    }

    /** Spring Security itself puts its composites around the proxy, here with Spring MVC as in an application. */
    @Test
    void springSecurityPutsItsCompositeAroundTheProxy() {
        AtomicReference<Boolean> seen = new AtomicReference<>();
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class, WebMvcAutoConfiguration.class))
                .withBean(BeanFactoryPostProcessor.class,
                        () -> beanFactory -> seen.set(ContexaOwnedChainDefinitionCheck.springChainProxySeesThroughDebug(beanFactory)))
                .run(context -> assertThat(context).hasNotFailed());

        assertThat(seen.get()).isTrue();
    }

    // ---- the refusal

    @Test
    void theRefusalSaysWhatTheLaterRefusalSays() {
        DefaultListableBeanFactory beans = contexaOwned(true);
        chain(beans, "hostChain", "fluent");

        assertThatThrownBy(() -> check("CONTEXA_OWNED").postProcessBeanFactory(beans))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    ContexaOperatingProfileException later = OwnershipStartupDiagnostics.applicationChainsRefused(List.of("hostChain"));
                    assertThat(refused.getMessage()).isEqualTo(later.getMessage()).isEqualTo("Contexa owns the sign-in of this"
                            + " application, but the application declares its own security chain(s) [hostChain]. Contexa's chain"
                            + " takes every request first, so they would never run and what they protect would be open.");
                    assertThat(refused.action()).isEqualTo(later.action());
                });
        assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseApplicationChains(
                List.of(new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of(new ServletRequestPathFilter()))), null))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> assertThat(refused.getMessage())
                        .isEqualTo(OwnershipStartupDiagnostics.applicationChainsRefused(List.of("any request")).getMessage()));
    }

    @Test
    void whereTheApplicationKeepsItsSignInNothingIsRefused() {
        DefaultListableBeanFactory beans = contexaOwned(true);
        chain(beans, "hostChain", "fluent");

        assertThatCode(() -> check("HOST_OWNED").postProcessBeanFactory(beans)).doesNotThrowAnyException();
        assertThatCode(() -> new ContexaOwnedChainDefinitionCheck().postProcessBeanFactory(beans)).doesNotThrowAnyException();
    }

    /** What the check cannot read lets the start go on, to the later refusal. */
    @Test
    void aFailureOfItsOwnReadingLetsTheStartGoOn() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory() {
            @Override
            public String[] getBeanNamesForType(Class<?> type, boolean includeNonSingletons, boolean allowEagerInit) {
                throw new IllegalStateException("unreadable");
            }
        };

        assertThatCode(() -> check("CONTEXA_OWNED").postProcessBeanFactory(beans)).doesNotThrowAnyException();
    }

    // ---- helpers

    private static boolean certain(Class<?> type, String method) throws Exception {
        return ContexaOwnedChainDefinitionCheck.returnsOnlyWhatHttpSecurityBuilds(type, type.getName(), method);
    }

    private static ContexaOwnedChainDefinitionCheck check(String ownership) {
        ContexaOwnedChainDefinitionCheck check = new ContexaOwnedChainDefinitionCheck();
        check.setEnvironment(new MockEnvironment().withProperty("contexa.bridge.ownership", ownership));
        return check;
    }

    /** What a start where Contexa owns the sign-in has: the later refusal, Spring Security's proxy and its HttpSecurity. */
    private static DefaultListableBeanFactory contexaOwned(boolean composite) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerBeanDefinition("aiSecurityConfiguration", new RootBeanDefinition(AiSecurityConfiguration.class));
        beans.registerBeanDefinition(ContexaOwnedChainDefinitionCheck.LATER_REFUSAL,
                beanMethod(AiSecurityConfiguration.class, "ownershipStartupDiagnostics", "aiSecurityConfiguration"));
        beans.registerBeanDefinition(WEB_SECURITY, new RootBeanDefinition(WebSecurityConfiguration.class));
        AbstractBeanDefinition proxy = beanMethod(WebSecurityConfiguration.class, PROXY, WEB_SECURITY);
        beans.registerBeanDefinition(PROXY, composite ? composite(composite(proxy, 0), 1) : proxy);
        RootBeanDefinition httpSecurity = new RootBeanDefinition(HttpSecurity.class);
        httpSecurity.setScope(AbstractBeanDefinition.SCOPE_PROTOTYPE);
        beans.registerBeanDefinition(ContexaOwnedChainDefinitionCheck.SPRING_HTTP_SECURITY, httpSecurity);
        beans.registerBeanDefinition("chains", new RootBeanDefinition(Chains.class));
        return beans;
    }

    /** As Spring Security replaces its proxy: a composite whose filters are a filter of its own and the proxy. */
    private static RootBeanDefinition composite(AbstractBeanDefinition wrapped, int which) {
        RootBeanDefinition composite = new RootBeanDefinition();
        composite.setBeanClassName(ContexaOwnedChainDefinitionCheck.SPRING_COMPOSITES.stream().sorted().toList().get(which));
        ManagedList<Object> filters = new ManagedList<>();
        filters.add(new RootBeanDefinition(ServletRequestPathFilter.class));
        filters.add(wrapped);
        composite.getConstructorArgumentValues().addIndexedArgumentValue(0, filters);
        return composite;
    }

    private static AbstractBeanDefinition chain(DefaultListableBeanFactory beans, String name, String method) {
        AbstractBeanDefinition definition = beanMethod(Chains.class, method, "chains");
        beans.registerBeanDefinition(name, definition);
        return definition;
    }

    /** A bean definition of a bean method, as the configuration class reader makes it. */
    private static AbstractBeanDefinition beanMethod(Class<?> configuration, String method, String factoryBean) {
        MethodMetadata metadata = AnnotationMetadata.introspect(configuration).getDeclaredMethods().stream()
                .filter(candidate -> candidate.getMethodName().equals(method))
                .findFirst()
                .orElseThrow();
        AnnotatedGenericBeanDefinition definition = new AnnotatedGenericBeanDefinition(AnnotationMetadata.introspect(configuration), metadata);
        definition.setFactoryBeanName(factoryBean);
        definition.setFactoryMethodName(method);
        return definition;
    }

    /** The shapes of chain methods; none of them is ever called here. */
    @SuppressWarnings("unused")
    static class Chains {

        private HttpSecurity held;
        private int finished;

        @Bean
        SecurityFilterChain fluent(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }

        @Bean
        SecurityFilterChain statementByStatement(HttpSecurity http) throws Exception {
            http.securityMatcher("/api/**");
            http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
            http.addFilterBefore(new ServletRequestPathFilter(), AnonymousAuthenticationFilter.class);
            return http.build();
        }

        @Bean
        DefaultSecurityFilterChain declaresTheDefaultChain(HttpSecurity http) throws Exception {
            return http.build();
        }

        @Bean
        SecurityFilterChain withOtherParameters(HttpSecurity http, String path) throws Exception {
            return http.securityMatcher(path).build();
        }

        @Bean
        static SecurityFilterChain staticMethod(HttpSecurity http) throws Exception {
            return http.build();
        }

        @Bean
        SecurityFilterChain throwsWhenItCannotBuild(HttpSecurity http, boolean ready) throws Exception {
            if (!ready) {
                throw new IllegalStateException("not ready");
            }
            return http.build();
        }

        @Bean
        SecurityFilterChain onACondition(HttpSecurity http, boolean enabled) throws Exception {
            if (enabled) {
                return http.build();
            }
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        }

        @Bean
        SecurityFilterChain nullOnACondition(HttpSecurity http, boolean enabled) throws Exception {
            return enabled ? http.build() : null;
        }

        @Bean
        SecurityFilterChain throughALocal(HttpSecurity http) throws Exception {
            SecurityFilterChain chain = http.build();
            return chain;
        }

        @Bean
        SecurityFilterChain throughAHelper(HttpSecurity http) throws Exception {
            return helper(http);
        }

        private SecurityFilterChain helper(HttpSecurity http) throws Exception {
            return http.build();
        }

        @Bean
        SecurityFilterChain withoutHttpSecurity() {
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        }

        @Bean
        SecurityFilterChain fromAProvider(ObjectProvider<HttpSecurity> provider) throws Exception {
            return provider.getObject().build();
        }

        @Bean
        SecurityFilterChain fromAField() throws Exception {
            return held.build();
        }

        @Bean
        SecurityFilterChain aFallbackOnFailure(HttpSecurity http) {
            try {
                return http.build();
            } catch (Exception e) {
                return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
            }
        }

        @Bean
        SecurityFilterChain withAFinallyBlock(HttpSecurity http) throws Exception {
            try {
                return http.build();
            } finally {
                finished++;
            }
        }

        @Bean
        OrderedSecurityFilterChain declaresContexasChain(HttpSecurity http) throws Exception {
            return new OrderedSecurityFilterChain(0, AnyRequestMatcher.INSTANCE, http.build().getFilters());
        }

        @Bean
        Object declaresAnything(HttpSecurity http) throws Exception {
            return http.build();
        }

        @Bean
        SecurityFilterChain overloaded(HttpSecurity http) throws Exception {
            return http.build();
        }

        SecurityFilterChain overloaded(HttpSecurity http, String path) throws Exception {
            return http.securityMatcher(path).build();
        }

        @Bean
        @SuppressWarnings("removal")
        SecurityFilterChain madeByHand(HttpSecurity http) throws Exception {
            return new HttpSecurity(null, null, null).build();
        }
    }

    static class OverridingChains extends Chains {

        @Override
        SecurityFilterChain fluent(HttpSecurity http) {
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        }
    }

    static class InheritingChains extends Chains {
    }

    static class Customizers {

        @Bean
        WebSecurityCustomizer customizer() {
            return web -> web.ignoring().requestMatchers("/static/**");
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity(debug = true)
    static class DebuggedSecurity {
    }
}
