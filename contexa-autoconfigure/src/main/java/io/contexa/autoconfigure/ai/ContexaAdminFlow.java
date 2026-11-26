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

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaAdminRealm;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityAuthDsl;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * The flow Contexa's administrators sign in with wherever they sign in apart from the application's users (R-13 of
 * docs/agent/운영모드-정상화-구현계획.md): an MFA flow of Contexa's on {@link ContexaAdminRealm#URL_PREFIX} only, ahead of
 * every other chain, whose rules {@code AdminRealmConfigurer} gives it. It is declared here once, for Contexa's default
 * configuration and for a configuration the application declares itself, which used to have no such flow: an application
 * that defined its sign-in with Contexa's DSL left Contexa's administrators no way to the console.
 * <p>
 * Where Contexa's main chain signs the application's users in with Contexa's own accounts (FULL with CONTEXA_OWNED) the
 * administrators and the users are one, and nothing is added, so that one person's sign-in is not split in two.
 */
public final class ContexaAdminFlow {

    private ContexaAdminFlow() {
    }

    /** Declares the flow: the password, then a passkey or a code by mail, under the console's prefix, in a session. */
    public static IdentityAuthDsl declare(IdentityAuthDsl dsl) throws Exception {
        return dsl.mfa(mfa -> mfa.name(ContexaSignInRealm.ADMIN_FLOW_NAME)
                        .urlPrefix(ContexaAdminRealm.URL_PREFIX)
                        .requiredFactors(1)
                        .primaryAuthentication(auth -> auth
                                .formLogin(form -> form.defaultSuccessUrl(ContexaAdminRealm.URL_PREFIX)))
                        .passkey(Customizer.withDefaults())
                        .ott(Customizer.withDefaults())
                        .order(ContexaAdminRealm.FLOW_ORDER))
                .session(Customizer.withDefaults());
    }

    /**
     * The configuration with the flow of Contexa's administrators after the flows it declares, its own customizer kept; the
     * same configuration where it already has that flow (by its name, {@link ContexaSignInRealm#ADMIN_FLOW_NAME}). The flows
     * of the application come first, so that whatever looks for the first multi-step flow still finds the application's.
     */
    public static PlatformConfig joinedTo(PlatformConfig config, ApplicationContext context) throws Exception {
        if (config.getFlows().stream().anyMatch(ContexaSignInRealm::isAdminFlow)) {
            return config;
        }
        IdentityDslRegistry<HttpSecurity> adminFlow = new IdentityDslRegistry<>(context);
        declare(adminFlow);
        PlatformConfig.Builder joined = PlatformConfig.builder().global(config.getGlobalCustomizer());
        config.getFlows().forEach(joined::addFlow);
        adminFlow.build().getFlows().forEach(joined::addFlow);
        PlatformConfig result = joined.build();
        result.setPlatformContext(config.getPlatformContext());
        return result;
    }

    /**
     * Gives every {@link PlatformConfig} of the context the flow of Contexa's administrators where they sign in apart from
     * the application's users. It replaces the bean as it is made, so that everything that reads the configuration (the
     * chains, the MFA policy, the flows' addresses) sees the one same set of flows. It is ordered with the first
     * post-processors, so that a configuration made while the later ones are being made is not missed.
     */
    public static final class PostProcessor implements BeanPostProcessor, PriorityOrdered, ApplicationContextAware {

        private ApplicationContext context;

        @Override
        public void setApplicationContext(ApplicationContext applicationContext) {
            this.context = applicationContext;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
            if (!(bean instanceof PlatformConfig config) || !adminRealmOnItsOwnChain()) {
                return bean;
            }
            try {
                return joinedTo(config, context);
            } catch (Exception e) {
                throw new BeanCreationException(beanName,
                        "The flow of Contexa's administrators could not be added to this PlatformConfig", e);
            }
        }

        private boolean adminRealmOnItsOwnChain() {
            return OperatingBehaviour.of(ContexaOperatingProfile.resolve(context.getEnvironment())).adminRealmOnItsOwnChain();
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE;
        }
    }
}
