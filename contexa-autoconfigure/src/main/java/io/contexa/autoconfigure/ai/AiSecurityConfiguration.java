package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
@Import(AiBridgeConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
public class AiSecurityConfiguration {

    /**
     * Creates a default {@link PlatformConfig} with MFA flow (formLogin + OTT) and session state.
     * <p>
     * Uses {@link IdentityDslRegistry} directly (not as a bean) to avoid the chicken-and-egg
     * problem: {@code IdentitySecurityCoreAutoConfiguration} creates the registry bean but
     * requires {@code PlatformConfig} to activate ({@code @ConditionalOnBean}).
     * <p>
     * The global customizer registers {@link AISessionSecurityContextRepository}
     * which is required for Zero Trust to function.
     * <p>
     * Once this bean exists, the existing configurer mechanism handles everything:
     * {@code GlobalConfigurer}, {@code ZeroTrustAccessControlConfigurer},
     * {@code ZeroTrustChallengeConfigurer}, and {@code SecurityFilterChainRegistrar}.
     */
    @Bean
    @ConditionalOnMissingBean(PlatformConfig.class)
    public PlatformConfig platformDslConfig(
            ApplicationContext applicationContext,
            AISessionSecurityContextRepository aiSessionSecurityContextRepository,
            ObjectProvider<BridgeResolutionFilter> bridgeResolutionFilterProvider) throws Exception {
        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(applicationContext);
        BridgeResolutionFilter bridgeResolutionFilter = bridgeResolutionFilterProvider.getIfAvailable();
        return registry
                .global(http -> {
                    http.securityContext(sc -> sc.securityContextRepository(aiSessionSecurityContextRepository));
                    if (bridgeResolutionFilter != null) {
                        http.addFilterBefore(bridgeResolutionFilter, UsernamePasswordAuthenticationFilter.class);
                    }
                })
                .mfa(mfa -> mfa
                        .primaryAuthentication(auth -> auth
                                .formLogin(form -> form.defaultSuccessUrl("/")))
                        .ott(Customizer.withDefaults())
                        .order(100))
                .session(Customizer.withDefaults())
                .build();
    }
}
