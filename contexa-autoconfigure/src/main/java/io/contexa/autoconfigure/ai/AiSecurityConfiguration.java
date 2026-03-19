package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacommon.security.bridge.AuthBridge;
import io.contexa.contexacommon.security.bridge.AuthBridgeFilter;
import io.contexa.contexacommon.security.bridge.NoOpAuthBridge;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SessionAuthBridge;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import java.util.UUID;

/**
 * Core configuration for {@code @EnableAISecurity}.
 * <p>
 * Supports two modes:
 * <ul>
 *   <li><b>FULL</b>: Contexa manages entire authentication (formLogin + MFA + Zero Trust)</li>
 *   <li><b>SANDBOX</b>: Legacy authentication bridged via AuthBridge. formLogin disabled via UUID.
 *       Contexa provides Zero Trust + MFA on top of legacy auth.</li>
 * </ul>
 */
@Slf4j
@Configuration
@ConditionalOnClass(SecurityFilterChain.class)
public class AiSecurityConfiguration {

    @Bean
    @ConditionalOnMissingBean(PlatformConfig.class)
    public PlatformConfig platformDslConfig(
            ApplicationContext applicationContext,
            AISessionSecurityContextRepository aiSessionSecurityContextRepository) throws Exception {

        SecurityMode mode = resolveSecurityMode();

        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(applicationContext);

        if (mode == SecurityMode.SANDBOX) {
            log.error("[Contexa] SANDBOX mode activated - bridging legacy authentication");
            AuthBridgeFilter bridgeFilter = createAuthBridgeFilter();

            return registry
                    .global(http -> http
                            .securityContext(sc -> sc.securityContextRepository(aiSessionSecurityContextRepository))
                            .addFilterAfter(bridgeFilter, SecurityContextHolderFilter.class))
                    .mfa(mfa -> mfa
                            .primaryAuthentication(auth -> auth
                                    .formLogin(form -> form
                                            .loginProcessingUrl("/" + UUID.randomUUID())
                                            .defaultSuccessUrl("/")))
                            .ott(Customizer.withDefaults())
                            .order(100))
                    .session(Customizer.withDefaults())
                    .build();
        }

        // FULL mode: default behavior
        return registry
                .global(http -> http
                        .securityContext(sc -> sc.securityContextRepository(aiSessionSecurityContextRepository)))
                .mfa(mfa -> mfa
                        .primaryAuthentication(auth -> auth
                                .formLogin(form -> form.defaultSuccessUrl("/")))
                        .ott(Customizer.withDefaults())
                        .order(100))
                .session(Customizer.withDefaults())
                .build();
    }

    private SecurityMode resolveSecurityMode() {
        String mode = System.getProperty(AiSecurityImportSelector.PROP_MODE);
        if (mode != null) {
            try {
                return SecurityMode.valueOf(mode);
            } catch (IllegalArgumentException ignored) {
            }
        }
        return SecurityMode.FULL;
    }

    private AuthBridgeFilter createAuthBridgeFilter() {
        AuthBridge bridge = createAuthBridge();
        return new AuthBridgeFilter(bridge);
    }

    private AuthBridge createAuthBridge() {
        String bridgeClassName = System.getProperty(AiSecurityImportSelector.PROP_AUTH_BRIDGE);

        if (bridgeClassName == null || bridgeClassName.equals(NoOpAuthBridge.class.getName())) {
            return new NoOpAuthBridge();
        }

        if (bridgeClassName.equals(SessionAuthBridge.class.getName())) {
            String attribute = System.getProperty(AiSecurityImportSelector.PROP_SESSION_USER_ATTR);
            if (attribute == null || attribute.isBlank()) {
                throw new IllegalStateException(
                        "@EnableAISecurity(authBridge=SessionAuthBridge.class) requires sessionUserAttribute to be set");
            }
            return new SessionAuthBridge(attribute);
        }

        // Custom AuthBridge: instantiate via default constructor
        try {
            Class<?> bridgeClass = Class.forName(bridgeClassName);
            return (AuthBridge) bridgeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to instantiate AuthBridge: " + bridgeClassName +
                            ". Ensure it has a public no-arg constructor.", e);
        }
    }
}
