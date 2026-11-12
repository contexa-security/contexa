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

import java.util.Locale;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class SecurityFilterChainRegistrar {
    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final Map<String, Class<? extends Filter>> stepFilterClasses;
    private final SecurityFilterChainCustomizer securityFilterChainCustomizer = new SecurityFilterChainCustomizer();

    public SecurityFilterChainRegistrar(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                        Map<String, Class<? extends Filter>> stepFilterClasses) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider, "ConfiguredFactorFilterProvider cannot be null.");
        this.stepFilterClasses = Objects.requireNonNull(stepFilterClasses, "stepFilterClasses cannot be null.");
    }

    public void registerSecurityFilterChains(List<FlowContext> flows, ApplicationContext context) {
        Assert.notNull(flows, "Flows list cannot be null.");
        Assert.notNull(context, "ApplicationContext cannot be null.");

        if (!(context instanceof ConfigurableApplicationContext cac)) {
            log.error("ApplicationContext is not a ConfigurableApplicationContext. Cannot register SecurityFilterChain beans dynamically.");
            return;
        }
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger idx = new AtomicInteger(0);
        List<BuiltFlow> built = new ArrayList<>();

        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null.");
            AuthenticationFlowConfig flowConfig = Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null.");
            String flowTypeName = Objects.requireNonNull(flowConfig.getTypeName(), "Flow typeName cannot be null.");

            String beanName = "contexa" + flowTypeName + "SecurityFilterChain" + idx.incrementAndGet();
            OrderedSecurityFilterChain chain = buildAndRegisterFilters(fc, context);
            built.add(new BuiltFlow(flowTypeName, chain.getOrder(), chain.getRequestMatcher()));
            BeanDefinition bd = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class, () -> chain)
                    .setLazyInit(false)
                    .setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
                    .getBeanDefinition();
            registry.registerBeanDefinition(beanName, bd);
        }
        unreachableFlows(built).forEach(log::error);
    }

    /** A flow's chain as the filter chain proxy orders and matches it. */
    record BuiltFlow(String typeName, int order, RequestMatcher requestMatcher) {
    }

    /**
     * The flows no request reaches: those ordered after a flow whose chain takes every request (no URL prefix, no
     * narrower OAuth2 request scope). Spring rejects such a chain only for its own chain type, so it is reported here.
     * Flows of the same order keep their registration order, as the filter chain proxy does.
     */
    static List<String> unreachableFlows(List<BuiltFlow> flows) {
        List<BuiltFlow> ordered = new ArrayList<>(flows);
        ordered.sort(Comparator.comparingInt(BuiltFlow::order));
        List<String> problems = new ArrayList<>();
        BuiltFlow takesEveryRequest = null;
        for (BuiltFlow flow : ordered) {
            if (takesEveryRequest != null) {
                problems.add("Flow '" + flow.typeName() + "' is never reached: flow '" + takesEveryRequest.typeName()
                        + "', ordered before it, takes every request. Give one of them a narrower scope and order it "
                        + "first: a urlPrefix, or for an OAuth2 flow "
                        + ".oauth2(oauth2 -> oauth2.requestScope(OAuth2RequestScope.TOKEN_REQUESTS)).");
            } else if (flow.requestMatcher() instanceof AnyRequestMatcher) {
                takesEveryRequest = flow;
            }
        }
        return problems;
    }

    /**
     * The password of an MFA flow is taken by the flow's own first step, which goes on to the factors. A form login of
     * Spring Security in the same chain (the application's {@code http.formLogin(...)} in the global customizer, or in
     * a {@code rawHttp} of the flow) is a second password sign-in that ends at the password: at its own address it
     * signed a user in beside the factors. It is taken out of the chain before the chain is built, and the start says
     * where its settings belong.
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static void keepThePasswordStepOfAnMfaFlowItsOwn(HttpSecurity http, AuthenticationFlowConfig flowConfig) {
        if (!MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            return;
        }
        keepThePasskeyAndCodeSignInOfAnMfaFlowItsOwn(http, flowConfig);
        if (http.getConfigurer(FormLoginConfigurer.class) == null) {
            return;
        }
        http.removeConfigurer((Class) FormLoginConfigurer.class);
        log.warn("Flow '{}': the form login of Spring Security written for this chain (http.formLogin(...) in the "
                        + "global customizer, or in a rawHttp of the flow) is not used. It would sign a user in with "
                        + "the password alone, beside the factors of this flow. The flow's own first step takes the "
                        + "password: write the settings there, mfa(mfa -> mfa.primaryAuthentication(auth -> "
                        + "auth.formLogin(form -> form.loginPage(...).failureUrl(...)))).",
                flowConfig.getTypeName());
    }

    /**
     * Spring Security's passkey sign-in ({@code http.webAuthn(...)}) and one-time code sign-in
     * ({@code http.oneTimeTokenLogin(...)}) written in the global customizer are added to every chain. In an MFA chain
     * whose flow has no factor of that kind they are a sign-in of their own, at Spring's addresses, with the passkey or
     * the mail code alone. A flow with the factor configures the same configurer as its factor, so nothing is taken
     * out then. A {@code rawHttp} of an MFA step that adds one is refused when the step is applied.
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static void keepThePasskeyAndCodeSignInOfAnMfaFlowItsOwn(HttpSecurity http, AuthenticationFlowConfig flowConfig) {
        if (!hasFactor(flowConfig, "PASSKEY") && http.getConfigurer(WebAuthnConfigurer.class) != null) {
            http.removeConfigurer((Class) WebAuthnConfigurer.class);
            log.warn("Flow '{}': the passkey sign-in of Spring Security written in the global customizer "
                            + "(http.webAuthn(...)) is not used in this chain. The flow has no passkey factor, and that "
                            + "sign-in would let a person in with the passkey alone, without the factors of this flow. "
                            + "Give the flow a passkey factor, mfa(mfa -> mfa.passkey(...)), or use a single passkey flow.",
                    flowConfig.getTypeName());
        }
        if (!hasFactor(flowConfig, "OTT") && http.getConfigurer(OneTimeTokenLoginConfigurer.class) != null) {
            http.removeConfigurer((Class) OneTimeTokenLoginConfigurer.class);
            log.warn("Flow '{}': the one-time code sign-in of Spring Security written in the global customizer "
                            + "(http.oneTimeTokenLogin(...)) is not used in this chain. The flow has no one-time code "
                            + "factor, and that sign-in would let a person in with the mail code alone, without the factors "
                            + "of this flow. Give the flow a code factor, mfa(mfa -> mfa.ott(...)), or use a single ott flow.",
                    flowConfig.getTypeName());
        }
    }

    private static boolean hasFactor(AuthenticationFlowConfig flowConfig, String kind) {
        return flowConfig.getStepConfigs() != null && flowConfig.getStepConfigs().stream()
                .anyMatch(step -> !step.isPrimary() && step.getType() != null
                        && step.getType().toUpperCase(Locale.ROOT).contains(kind));
    }

    public OrderedSecurityFilterChain buildAndRegisterFilters(FlowContext fc, ApplicationContext appContext) {
        try {
            AuthenticationFlowConfig flowConfig = fc.flow();
            keepThePasswordStepOfAnMfaFlowItsOwn(fc.http(), flowConfig);
            DefaultSecurityFilterChain builtChain = fc.http().build();
            securityFilterChainCustomizer.customize(builtChain, flowConfig, appContext,
                    fc.http().getSharedObject(SessionAuthenticationStrategy.class));

            for (AuthenticationStepConfig step : flowConfig.getStepConfigs()) {
                Objects.requireNonNull(step, "AuthenticationStepConfig in flow cannot be null.");
                String pureFactorType = Objects.requireNonNull(step.getType(), "Step type cannot be null.").toLowerCase(Locale.ROOT);
                String stepId = step.getStepId();

                if (!StringUtils.hasText(stepId)) {
                    log.error("CRITICAL: AuthenticationStepConfig (type: {}, order: {}) in flow '{}' is missing a stepId. " +
                                    "This step's filter cannot be registered in ConfiguredFactorFilterProvider.",
                            pureFactorType, step.getOrder(), flowConfig.getTypeName());
                    continue;
                }

                if (MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName()) && step.getOrder() == 0) {
                    continue;
                }

                Class<? extends Filter> filterClass = stepFilterClasses.get(pureFactorType);
                if (filterClass == null) {
                    log.error("No filter class configured in stepFilterClasses for step type: '{}' (id: {}) in flow: '{}'",
                            pureFactorType, stepId, flowConfig.getTypeName());
                    throw new IllegalStateException("Filter class not configured: " + pureFactorType + " (flow: " + flowConfig.getTypeName() + ")");
                }

                Optional<Filter> foundFilterOptional = builtChain.getFilters().stream()
                        .filter(filterClass::isInstance)
                        .findFirst();

                if (foundFilterOptional.isEmpty()) {
                    log.error("Filter of type {} not found in the built SecurityFilterChain for step: '{}' in flow: '{}'. Critical configuration error.",
                            filterClass.getName(), stepId, flowConfig.getTypeName());
                    throw new IllegalStateException("Filter instance not found in built chain: " + stepId + " (flow: " + flowConfig.getTypeName() + ")");
                }

                Filter actualFilterInstance = foundFilterOptional.get();
                FactorIdentifier registrationKey = FactorIdentifier.of(flowConfig.getTypeName(), stepId);
                configuredFactorFilterProvider.registerFilter(registrationKey, actualFilterInstance);
            }

            return new OrderedSecurityFilterChain(
                    Ordered.HIGHEST_PRECEDENCE + flowConfig.getOrder(),
                    builtChain.getRequestMatcher(),
                    builtChain.getFilters()
            );
        } catch (Exception e) {
            log.error("Error building SecurityFilterChain or registering factor filters for flow: {}", fc.flow().getTypeName(), e);
            throw new RuntimeException("Failed to build SecurityFilterChain for flow " + fc.flow().getTypeName(), e);
        }
    }
}
