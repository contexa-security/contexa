package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.BridgeResolutionConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SessionSecurityContextRepositoryConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
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
     * Once this bean exists, the existing configurer mechanism handles everything:
     * {@code GlobalConfigurer}, {@code ZeroTrustAccessControlConfigurer},
     * {@code ZeroTrustChallengeConfigurer}, and {@code SecurityFilterChainRegistrar}.
     */
    @Bean
    @ConditionalOnMissingBean(PlatformConfig.class)
    public PlatformConfig platformDslConfig(
            ApplicationContext applicationContext,
            AISessionSecurityContextRepository aiSessionSecurityContextRepository) throws Exception {
        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(applicationContext);
        SecurityMode securityMode = resolveSecurityMode();

        if (securityMode == SecurityMode.SANDBOX) {
            return registry
                    .global(http -> {
                        http.csrf(AbstractHttpConfigurer::disable);
                        http.cors(AbstractHttpConfigurer::disable);
                        http.headers(AbstractHttpConfigurer::disable);
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
                .global(http -> {})
                .mfa(mfa -> mfa.requiredFactors(1)
                        .primaryAuthentication(auth -> auth
                                .formLogin(form -> form.defaultSuccessUrl("/")))
                        .passkey(Customizer.withDefaults())
                        .ott(Customizer.withDefaults())
                        .order(100))
                .session(Customizer.withDefaults())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AISessionSecurityContextRepository.class)
    public SessionSecurityContextRepositoryConfigurer sessionSecurityContextRepositoryConfigurer(
            AISessionSecurityContextRepository aiSessionSecurityContextRepository) {
        return new SessionSecurityContextRepositoryConfigurer(aiSessionSecurityContextRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(BridgeResolutionFilter.class)
    public BridgeResolutionConfigurer bridgeResolutionConfigurer(
            ObjectProvider<BridgeResolutionFilter> bridgeResolutionFilterProvider) {
        return new BridgeResolutionConfigurer(bridgeResolutionFilterProvider.getIfAvailable());
    }

    private SecurityMode resolveSecurityMode() {
        String configuredMode = System.getProperty(AiSecurityImportSelector.PROP_MODE);
        if (configuredMode == null || configuredMode.isBlank()) {
            return SecurityMode.SANDBOX;
        }
        try {
            return SecurityMode.valueOf(configuredMode.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return SecurityMode.SANDBOX;
        }
    }
}
