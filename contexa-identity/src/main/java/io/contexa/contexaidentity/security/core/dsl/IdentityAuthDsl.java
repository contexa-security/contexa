package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


public interface IdentityAuthDsl {

    
    IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer);

    
    IdentityStateDsl form(Customizer<FormConfigurerConfigurer> customizer) throws Exception; 

    
    IdentityStateDsl rest(Customizer<RestConfigurerConfigurer> customizer) throws Exception;

    
    IdentityStateDsl ott(Customizer<OttConfigurerConfigurer> customizer) throws Exception;

    
    IdentityStateDsl passkey(Customizer<PasskeyConfigurerConfigurer> customizer) throws Exception;

    
    IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception;

    
    

    
    PlatformConfig build();
}

