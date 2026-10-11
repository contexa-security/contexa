package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Login method names recorded by the identity module normalize onto the authentication type vocabulary; a one-time
 * code login is not read as an API token (W1-4).
 */
class AuthenticationTypeNormalizationTest {

    @Test
    void recordedLoginMethodsNormalize() {
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSWORD")).isEqualTo("PASSWORD");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSWORD+ONE_TIME_CODE")).isEqualTo("PASSWORD");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("ONE_TIME_CODE")).isEqualTo("ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("RECOVERY_CODE")).isEqualTo("ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSKEY")).isEqualTo("PASSKEY");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("JwtAuthenticationToken")).isEqualTo("TOKEN");
    }
}
