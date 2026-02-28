package io.contexa.springbootstartercontexaenterprise;

import io.contexa.contexacore.security.AIReactiveSecurityContextRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/*
@AutoConfiguration
@RequiredArgsConstructor
@EnableWebSecurity
public class PlatformSecurityConfigAutoConfiguration {

    private final AIReactiveSecurityContextRepository aiReactiveSecurityContextRepository;

    @Bean
    @ConditionalOnMissingBean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {
        return registry
                .global( http -> http.securityContext(sc -> sc.securityContextRepository(aiReactiveSecurityContextRepository)))
                .mfa(mfa -> mfa
                        .primaryAuthentication(auth -> auth.formLogin(form -> form.defaultSuccessUrl("/")))
                        .ott(Customizer.withDefaults())
                        .order(100)
                ).session(Customizer.withDefaults())
                .build();
    }
}*/
