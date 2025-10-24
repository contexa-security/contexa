package io.contexa.contexaidentity.security.core.mfa.configurer;

import io.contexa.contexaidentity.security.core.mfa.RetryPolicy;

/**
 * RetryPolicy 빌더용 DSL 인터페이스
 */
public interface RetryPolicyDslConfigurer{
    RetryPolicyDslConfigurer maxAttempts(int max);
    RetryPolicyDslConfigurer lockoutSec(long seconds);
    RetryPolicy build();
}
