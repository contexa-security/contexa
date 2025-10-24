package io.contexa.contexaidentity.security.core.mfa.configurer;

import io.contexa.contexaidentity.security.core.mfa.RetryPolicy;

/**
 * RetryPolicy DSL 구현체: 재시도 및 잠금 정책 설정
 */
public class RetryPolicyDslConfigurerImpl implements RetryPolicyDslConfigurer {
    private int maxAttempts = 1;
    private long lockoutSec = 0;

    @Override
    public RetryPolicyDslConfigurer maxAttempts(int max) {
        this.maxAttempts = max;
        return this;
    }

    @Override
    public RetryPolicyDslConfigurer lockoutSec(long seconds) {
        this.lockoutSec = seconds;
        return this;
    }

    @Override
    public RetryPolicy build() {
        return new RetryPolicy(maxAttempts);
    }
}