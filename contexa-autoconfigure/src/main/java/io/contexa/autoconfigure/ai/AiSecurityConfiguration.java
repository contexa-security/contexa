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

import io.contexa.contexacommon.security.ContexaConsolePaths;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.AdminRealmConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.BridgeResolutionConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SessionSecurityContextRepositoryConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.autoconfigure.iam.IamSecurityCoreAutoConfiguration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Core configuration for {@code @EnableAISecurity} legacy integration.
 * <p>
 * Provides a default {@link PlatformConfig} using {@link IdentityDslRegistry}
 * when no custom {@code PlatformConfig} bean exists. This triggers
 * {@code IdentitySecurityCoreAutoConfiguration} which creates all Zero Trust
 * beans and registers security filter chains via the configurer mechanism.
 *
 * @see io.contexa.contexacommon.annotation.EnableAISecurity
 */
@Configuration
@Import({AiBridgeConfiguration.class, ContexaFilterSlotConfiguration.class, HostHealthConfiguration.class,
        HostMailHealthConfiguration.class, SandboxDiagnosticsConfiguration.class})
@ConditionalOnClass(SecurityFilterChain.class)
public class AiSecurityConfiguration {

    private final Environment environment;

    public AiSecurityConfiguration(Environment environment) {
        this.environment = environment;
    }


    /**
     * Creates a default {@link PlatformConfig} with MFA flow (formLogin + OTT) and session state.
     * <p>
     * Uses {@link IdentityDslRegistry} directly (not as a bean) to avoid the chicken-and-egg
     * problem: {@code IdentitySecurityCoreAutoConfiguration} creates the registry bean but
     * requires {@code PlatformConfig} to activate ({@code @ConditionalOnBean}).
     * <p>
     * Once this bean exists, the existing configurer mechanism handles everything:
     * {@code GlobalConfigurer}, {@code ZeroTrustAccessControlConfigurer},
     * {@code ZeroTrustChallengeConfigurer}, and {@code SecurityFilterChainRegistrar}.
     * <p>
     * Wherever Contexa's administrators sign in apart from the application's users, it carries their flow
     * ({@link ContexaAdminFlow}), as a configuration the application declares itself does.
     */
    @Bean(name = "contexaPlatformDslConfig")
    @ConditionalOnMissingBean(PlatformConfig.class)
    public PlatformConfig platformDslConfig(ApplicationContext applicationContext,
                                               CustomDynamicAuthorizationManager contexaCustomDynamicAuthorizationManager) throws Exception {
        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(applicationContext);
        OperatingBehaviour behaviour = OperatingBehaviour.of(ContexaOperatingProfile.resolve(environment));
        // FULL: Contexa's main chain signs the application's users in and authorizes every request by policy. SANDBOX builds
        // no main chain: the application's own chain stays the main one, and Contexa enforces behind it.
        if (behaviour.buildsMainChain()) {
            SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> http
                    .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers("/contexa/css/**", "/contexa/js/**", "/contexa/img/**", "/images/**", "/favicon.ico",
                                    ContexaConsolePaths.PASSWORD_CHANGE).permitAll()
                            .anyRequest().access(contexaCustomDynamicAuthorizationManager));
            registry.global(globalHttpCustomizer)
                    .mfa(mfa -> mfa.requiredFactors(1)
                            .primaryAuthentication(auth -> auth
                                    .formLogin(form -> form.defaultSuccessUrl("/")))
                            .passkey(Customizer.withDefaults())
                            .ott(Customizer.withDefaults())
                            .order(100))
                    .session(Customizer.withDefaults());
        }
        if (behaviour.adminRealmOnItsOwnChain()) {
            ContexaAdminFlow.declare(registry);
        }
        return registry.build();
    }

    /**
     * The flow of Contexa's administrators for a {@link PlatformConfig} the application declares itself, which takes the
     * place of the default one above (R-13): see {@link ContexaAdminFlow}. Static, as a post-processor is made before the
     * configuration classes.
     */
    @Bean(name = "contexaAdminFlowPostProcessor")
    public static ContexaAdminFlow.PostProcessor contexaAdminFlowPostProcessor() {
        return new ContexaAdminFlow.PostProcessor();
    }

    @Bean(name = "contexaSessionSecurityContextRepositoryConfigurer")
    @ConditionalOnMissingBean
    public SessionSecurityContextRepositoryConfigurer sessionSecurityContextRepositoryConfigurer(
            ConfigurableListableBeanFactory beanFactory) {
        return new SessionSecurityContextRepositoryConfigurer(
                ContexaOwnBeans.ownIfPresent(beanFactory, IamSecurityCoreAutoConfiguration.SESSION_CONTEXT_REPOSITORY,
                        AISessionSecurityContextRepository.class),
                ContexaOwnBeans.ownIfPresent(beanFactory, IamSecurityCoreAutoConfiguration.ADMIN_SESSION_CONTEXT_REPOSITORY,
                        AISessionSecurityContextRepository.class));
    }

    /** The rules of the chain of Contexa's administrators (R-13): its requests, its keys, its sign-out. */
    @Bean(name = "contexaAdminRealmConfigurer")
    @ConditionalOnMissingBean
    public AdminRealmConfigurer adminRealmConfigurer() {
        return new AdminRealmConfigurer();
    }

    @Bean(name = "contexaBridgeResolutionConfigurer")
    @ConditionalOnMissingBean
    public BridgeResolutionConfigurer bridgeResolutionConfigurer(
            ObjectProvider<BridgeResolutionFilter> bridgeResolutionFilterProvider) {
        return new BridgeResolutionConfigurer(bridgeResolutionFilterProvider.getIfAvailable());
    }

    /** What an installation should know at start about its ownership (findings F-1, F-2, F-8). */
    @Bean(name = "contexaOwnershipStartupDiagnostics")
    @ConditionalOnMissingBean
    public OwnershipStartupDiagnostics ownershipStartupDiagnostics(ConfigurableListableBeanFactory beanFactory) {
        return new OwnershipStartupDiagnostics(beanFactory, ContexaOperatingProfile.resolve(environment),
                environment.getProperty("contexa.startup.class-path-report", Boolean.class, true));
    }

    /** The refusal of WebFlux routes from their bean definitions, before Contexa touches its database (PR-174). */
    @Bean(name = "contexaReactiveRoutesDefinitionCheck")
    public static ReactiveRoutesDefinitionCheck reactiveRoutesDefinitionCheck() {
        return new ReactiveRoutesDefinitionCheck();
    }
}
