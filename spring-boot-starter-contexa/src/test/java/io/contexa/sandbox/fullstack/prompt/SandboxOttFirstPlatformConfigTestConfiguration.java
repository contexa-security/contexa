package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * Sandbox-only PlatformConfig override for full-stack replay tests.
 *
 * Purpose:
 * - Keep production PlatformSecurityConfig untouched.
 * - Force OTT-based MFA in sandbox replay so WebClient can complete the real MFA state machine.
 * - Reuse the same authorization manager and AI session repository as production.
 */
@TestConfiguration(proxyBeanMethods = false)
public class SandboxOttFirstPlatformConfigTestConfiguration {

    @Bean(name = "platformDslConfig")
    public PlatformConfig platformDslConfig(
            IdentityDslRegistry<HttpSecurity> registry,
            CustomDynamicAuthorizationManager customDynamicAuthorizationManager,
            AISessionSecurityContextRepository aiSessionSecurityContextRepository) throws Exception {

        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authReq -> authReq
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico", "/password-change").permitAll()
                        .anyRequest().access(customDynamicAuthorizationManager))
                .securityContext(sc -> sc.securityContextRepository(aiSessionSecurityContextRepository));

        return registry
                .global(globalHttpCustomizer)
                .mfa(mfa -> mfa.urlPrefix("/admin")
                        .requiredFactors(1)
                        .primaryAuthentication(auth -> auth.formLogin(form -> form
                                .defaultSuccessUrl("/admin/test/security")))
                        .ott(Customizer.withDefaults())
                        .order(90))
                .session(Customizer.withDefaults())
                .build();
    }
}
