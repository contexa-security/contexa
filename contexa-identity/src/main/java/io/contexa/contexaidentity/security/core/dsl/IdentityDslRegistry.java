package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import io.contexa.contexacommon.enums.AuthType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Objects;

@Slf4j
public final class IdentityDslRegistry<H extends HttpSecurityBuilder<H>> 
        extends AbstractFlowRegistrar<H> implements IdentityAuthDsl {

    public IdentityDslRegistry(ApplicationContext applicationContext) {
        super(PlatformConfig.builder(),
                Objects.requireNonNull(applicationContext, "applicationContext cannot be null")
        );
            }

    @Override
    public IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer) {
        Objects.requireNonNull(customizer, "global customizer cannot be null");
        platformBuilder.global(customizer); 
                return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.FORM, customizer, 100, FormConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.REST, customizer, 200, RestConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.OTT, customizer, 300, OttConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.PASSKEY, customizer, 400, PasskeyConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception {
                return registerMultiStepFlow(customizer);
    }

    @Override
    public PlatformConfig build() {
        PlatformConfig config = platformBuilder.build();
                return config;
    }
}
