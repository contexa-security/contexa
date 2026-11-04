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
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.BridgeResolutionConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SessionSecurityContextRepositoryConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

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
@Import({AiBridgeConfiguration.class, HostOwnedHealthConfiguration.class, HostOwnedDiagnosticsConfiguration.class})
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
     */
    @Bean(name = "contexaPlatformDslConfig")
    @ConditionalOnMissingBean(PlatformConfig.class)
    public PlatformConfig platformDslConfig(ApplicationContext applicationContext,
                                               CustomDynamicAuthorizationManager contexaCustomDynamicAuthorizationManager) throws Exception {
        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(applicationContext);
        SecurityMode securityMode = ContexaOperatingProfile.resolve(environment).mode();
        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
            http
                    .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers("/contexa/css/**", "/contexa/js/**", "/contexa/img/**", "/images/**", "/favicon.ico",
                                    ContexaConsolePaths.PASSWORD_CHANGE).permitAll()
                            .anyRequest().access(contexaCustomDynamicAuthorizationManager)
                    )
            ;
        };

        if (securityMode == SecurityMode.SANDBOX) {
            return registry
                    .global(http -> {
                        http.csrf(AbstractHttpConfigurer::disable);
                        http.cors(AbstractHttpConfigurer::disable);
                        http.headers(AbstractHttpConfigurer::disable);
                        // The admin area is for administrators; a signed-in user keeps the self-service paths
                        // (asking for the release of a block, following a pending analysis), as the seed policies do.
                        http.authorizeHttpRequests(authReq -> authReq
                                .requestMatchers("/contexa/admin/login").permitAll()
                                .requestMatchers("/contexa/admin/api/aiam/zero-trust/**",
                                        "/contexa/admin/api/aiam/sse/zero-trust/**").authenticated()
                                .requestMatchers("/contexa/admin/**").hasAuthority("ROLE_ADMIN")
                                .anyRequest().permitAll());

                    })
                    .mfa(mfa -> mfa.requiredFactors(1)
                            .primaryAuthentication(auth -> auth
                                    .formLogin(form -> form
                                            .loginProcessingUrl("/" + UUID.randomUUID())
                                            .defaultSuccessUrl("/")))
                            .passkey(Customizer.withDefaults())
                            .ott(Customizer.withDefaults())
                            .order(100))
                    .session(Customizer.withDefaults())
                    .build();
        }

        return registry
                .global(globalHttpCustomizer)
                .mfa(mfa -> mfa.requiredFactors(1)
                        .primaryAuthentication(auth -> auth
                                .formLogin(form -> form.defaultSuccessUrl("/")))
                        .passkey(Customizer.withDefaults())
                        .ott(Customizer.withDefaults())
                        .order(100))
                .session(Customizer.withDefaults())
                .build();
    }

    @Bean(name = "contexaSessionSecurityContextRepositoryConfigurer")
    @ConditionalOnMissingBean
    public SessionSecurityContextRepositoryConfigurer sessionSecurityContextRepositoryConfigurer(
            ObjectProvider<AISessionSecurityContextRepository> aiSessionSecurityContextRepositoryProvider) {
        return new SessionSecurityContextRepositoryConfigurer(
                aiSessionSecurityContextRepositoryProvider.getIfAvailable());
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
        return new OwnershipStartupDiagnostics(beanFactory, ContexaOperatingProfile.resolve(environment));
    }
}
