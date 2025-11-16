package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.MfaAsepAttributes;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SecurityConfigurerDsl;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.Customizer;

public interface MfaDslConfigurer extends SecurityConfigurerDsl { // SecurityConfigurerDsl 마커 인터페이스 (선택적)
    MfaDslConfigurer order(int order);
    MfaDslConfigurer form(Customizer<FormConfigurerConfigurer> formConfigurer); // MFA의 한 단계로 Form 인증 사용
    MfaDslConfigurer rest(Customizer<RestConfigurerConfigurer> restConfigurer); // MFA의 한 단계로 Rest 인증 사용
    MfaDslConfigurer ott(Customizer<OttConfigurerConfigurer> ottConfigurer);   // MFA의 한 단계로 OTT 인증 사용
    MfaDslConfigurer passkey(Customizer<PasskeyConfigurerConfigurer> passkeyConfigurer); // MFA의 한 단계로 Passkey 인증 사용
    MfaDslConfigurer mfaFailureHandler(PlatformAuthenticationFailureHandler failureHandler);
    MfaDslConfigurer mfaSuccessHandler(PlatformAuthenticationSuccessHandler successHandler);
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);
    AuthenticationFlowConfig build(); // 최종적으로 AuthenticationFlowConfig 객체 반환
    MfaDslConfigurer asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer);
    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);
    MfaDslConfigurer mfaPage(Customizer<MfaPageConfigurer> mfaPageConfigurer);
}