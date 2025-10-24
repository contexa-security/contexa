package io.contexa.contexaidentity.security.core.mfa;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import lombok.Getter;

/**
 * MFA Factor별 재시도 정책을 정의하는 클래스 또는 인터페이스.
 */
@Getter
public class RetryPolicy { // 또는 interface RetryPolicy { int getMaxAttempts(); }

    private final int maxAttempts;
    // 추가적으로 재시도 간격, 잠금 정책 등을 포함할 수 있음

    public RetryPolicy(int maxAttempts) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("Max attempts must be at least 1.");
        }
        this.maxAttempts = maxAttempts;
    }

    // 기본 재시도 정책 (예: 3회)
    public static RetryPolicy defaultPolicy() {
        return new RetryPolicy(3);
    }

    public boolean canRetry(FactorContext factorContext, String stepId) {
        return true;
    }
}
