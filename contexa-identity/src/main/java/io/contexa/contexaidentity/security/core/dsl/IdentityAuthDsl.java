package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 플랫폼의 최상위 인증 DSL 인터페이스.
 * 다양한 인증 방식(form, rest, ott, passkey, mfa)을 설정하고,
 * 각 인증 방식 설정 후 상태 관리(session, jwt, oauth2)를 선택할 수 있도록 합니다.
 */
public interface IdentityAuthDsl {

    /**
     * 모든 SecurityFilterChain에 적용될 글로벌 HttpSecurity 설정을 커스터마이징합니다.
     * @param customizer HttpSecurity를 직접 커스터마이징하는 SafeHttpCustomizer
     * @return DSL 체이닝을 위한 현재 인스턴스
     */
    IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer);

    /**
     * Form 기반 인증 방식을 설정합니다.
     * @param customizer FormDslConfigurer를 커스터마이징합니다. (이 내부에서 .asep() 호출 가능)
     * @return 다음 단계인 IdentityStateDsl (상태 관리 설정)
     */
    IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) throws Exception; // throws Exception 추가 (asep() 때문에)

    /**
     * REST API 기반 인증 방식을 설정합니다.
     * @param customizer RestDslConfigurer를 커스터마이징합니다.
     * @return 다음 단계인 IdentityStateDsl
     */
    IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) throws Exception;

    /**
     * OTT (One Time Token) 인증 방식을 설정합니다.
     * @param customizer OttDslConfigurer를 커스터마이징합니다.
     * @return 다음 단계인 IdentityStateDsl
     */
    IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) throws Exception;

    /**
     * Passkey (WebAuthn) 인증 방식을 설정합니다.
     * @param customizer PasskeyDslConfigurer를 커스터마이징합니다.
     * @return 다음 단계인 IdentityStateDsl
     */
    IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) throws Exception;

    /**
     * MFA (Multi-Factor Authentication) 흐름을 설정합니다.
     * @param customizer MfaDslConfigurer를 커스터마이징합니다.
     * @return 다음 단계인 IdentityStateDsl
     */
    IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception;

    // RECOVERY_CODE를 단일 인증 흐름으로 사용할 경우 (선택적)
    // IdentityStateDsl recoveryCode(Customizer<RecoveryCodeDslConfigurer> customizer) throws Exception;

    /**
     * 모든 DSL 설정을 완료하고 최종 PlatformConfig 객체를 빌드합니다.
     * @return 빌드된 PlatformConfig 객체
     */
    PlatformConfig build();
}

