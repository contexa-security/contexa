package io.contexa.contexaidentity.security.core.mfa.configurer;

import io.contexa.contexaidentity.security.core.mfa.RecoveryConfig;

/**
 * MFA 전역 복구 정책 설정을 위한 DSL 구현체.
 */
public class RecoveryDslConfigurerImpl implements RecoveryDslConfigurer {
    private String emailOtpEndpoint;
    private String smsOtpEndpoint;

    // 생성자는 기본값 설정 등을 위해 유지 가능
    public RecoveryDslConfigurerImpl() {
    }

    @Override
    public RecoveryDslConfigurer emailOtpEndpoint(String endpoint) {
        this.emailOtpEndpoint = endpoint;
        return this;
    }

    @Override
    public RecoveryDslConfigurer smsOtpEndpoint(String endpoint) {
        this.smsOtpEndpoint = endpoint;
        return this;
    }

    @Override
    public RecoveryConfig build() {
        // RecoveryConfig 생성 시 필요한 값들이 모두 설정되었는지 Assert 등을 통해 검증 가능
        return new RecoveryConfig(emailOtpEndpoint, smsOtpEndpoint);
    }

}

