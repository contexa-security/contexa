package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import io.contexa.contexaidentity.security.enums.AuthType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Objects;

@Slf4j
public final class IdentityDslRegistry<H extends HttpSecurityBuilder<H>> // H는 형식적으로 유지
        extends AbstractFlowRegistrar<H> implements IdentityAuthDsl {

    public IdentityDslRegistry(ApplicationContext applicationContext) {
        super(PlatformConfig.builder(),
                Objects.requireNonNull(applicationContext, "applicationContext cannot be null")
        );
        log.info("IdentityDslRegistry initialized with ApplicationContext.");
    }

    @Override
    public IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer) {
        Objects.requireNonNull(customizer, "global customizer cannot be null");
        platformBuilder.global(customizer); // PlatformConfig.Builder에 저장
        log.debug("Global HttpSecurity customizer registered in PlatformConfig.Builder.");
        return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormConfigurerConfigurer> customizer) throws Exception {
        log.debug("Registering Form authentication options.");
        return registerAuthenticationMethod(AuthType.FORM, customizer, 100, FormConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestConfigurerConfigurer> customizer) throws Exception {
        log.debug("Registering Rest authentication options.");
        return registerAuthenticationMethod(AuthType.REST, customizer, 200, RestConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttConfigurerConfigurer> customizer) throws Exception {
        log.debug("Registering OTT authentication options.");
        return registerAuthenticationMethod(AuthType.OTT, customizer, 300, OttConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyConfigurerConfigurer> customizer) throws Exception {
        log.debug("Registering Passkey authentication options.");
        return registerAuthenticationMethod(AuthType.PASSKEY, customizer, 400, PasskeyConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception {
        log.debug("Registering MFA (Multi-Factor Authentication) flow options.");
        return registerMultiStepFlow(customizer);
    }

    @Override
    public PlatformConfig build() {
        PlatformConfig config = platformBuilder.build();
        log.info("PlatformConfig built with {} authentication flows.", config.getFlows().size());
        return config;
    }
}
