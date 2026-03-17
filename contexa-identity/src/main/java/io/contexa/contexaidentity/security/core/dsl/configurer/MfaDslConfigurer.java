package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.MfaAsepAttributes;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SecurityConfigurerDsl;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.Customizer;

public interface MfaDslConfigurer extends SecurityConfigurerDsl {
    MfaDslConfigurer name(String flowName);
    MfaDslConfigurer urlPrefix(String urlPrefix);
    MfaDslConfigurer order(int order);
    MfaDslConfigurer form(Customizer<FormConfigurerConfigurer> formConfigurer); 
    MfaDslConfigurer rest(Customizer<RestConfigurerConfigurer> restConfigurer); 
    MfaDslConfigurer ott(Customizer<OttConfigurerConfigurer> ottConfigurer);   
    MfaDslConfigurer passkey(Customizer<PasskeyConfigurerConfigurer> passkeyConfigurer); 
    MfaDslConfigurer mfaFailureHandler(PlatformAuthenticationFailureHandler failureHandler);
    MfaDslConfigurer mfaSuccessHandler(PlatformAuthenticationSuccessHandler successHandler);
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);
    AuthenticationFlowConfig build(); 
    MfaDslConfigurer asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer);
    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);
    MfaDslConfigurer mfaPage(Customizer<MfaPageConfigurer> mfaPageConfigurer);
}