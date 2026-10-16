package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Login method names recorded by the identity module normalize onto the authentication type vocabulary; a one-time
 * code login is not read as an API token (W1-4).
 */
class AuthenticationTypeNormalizationTest {

    @Test
    void recordedLoginMethodsNormalize() {
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSWORD")).isEqualTo("PASSWORD");
        // W5-10 D6: a login of two methods keeps both (it was PASSWORD, the second factor lost).
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSWORD+ONE_TIME_CODE"))
                .isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("ONE_TIME_CODE")).isEqualTo("ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("RECOVERY_CODE")).isEqualTo("ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSKEY")).isEqualTo("PASSKEY");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("JwtAuthenticationToken")).isEqualTo("TOKEN");
    }

    @Test
    void aLoginOfSeveralMethodsKeepsThemAllInTheRecordedOrder() {
        // W5-10 D6: the methods in the one order of the recorded names (AuthenticationMethodReferences), once each.
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("ONE_TIME_CODE+PASSWORD"))
                .isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("password+one-time-code"))
                .isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSWORD+PASSKEY")).isEqualTo("PASSWORD+PASSKEY");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("PASSWORD+PASSWORD")).isEqualTo("PASSWORD");
        assertThat(SecuritySemanticNormalizer.normalizeAuthenticationType("RECOVERY_CODE+ONE_TIME_CODE"))
                .isEqualTo("ONE_TIME_CODE");
    }

    @Test
    void anEarlierBuildReadsTheNewNameAsItReadTheRecordedOne() {
        // W5-7 D7 with W5-10 D6: the build before reads a name of several methods as its first known method, the same
        // as it read the name the identity module recorded; a rollback needs no second record of the old value.
        for (String recorded : List.of("PASSWORD+ONE_TIME_CODE", "PASSWORD+PASSKEY", "ONE_TIME_CODE+RECOVERY_CODE",
                "PASSWORD", "PASSKEY", "UsernamePasswordAuthenticationToken", "JwtAuthenticationToken", "mfa")) {
            assertThat(earlierBuild(SecuritySemanticNormalizer.normalizeAuthenticationType(recorded)))
                    .as(recorded).isEqualTo(earlierBuild(recorded));
        }
    }

    /** The login classifier of vocabulary vocab-2026.10.15, as that build reads a value. */
    private static String earlierBuild(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String candidate = value.trim().replace('-', '_').replace(' ', '_').toUpperCase(Locale.ROOT);
        if (containsAny(candidate, "PASSKEY", "WEBAUTHN", "FIDO")) {
            return "PASSKEY";
        }
        if (containsAny(candidate, "SAML", "OIDC", "OAUTH", "SSO")) {
            return "SSO";
        }
        if (containsAny(candidate, "USERNAMEPASSWORD", "PASSWORD")) {
            return "PASSWORD";
        }
        if (containsAny(candidate, "ONE_TIME_CODE", "RECOVERY_CODE")) {
            return "ONE_TIME_CODE";
        }
        if (containsAny(candidate, "SESSION", "SECURITY_CONTEXT")) {
            return "SESSION";
        }
        if (containsAny(candidate, "BEARER", "JWT", "APIKEY", "TOKEN")) {
            return "TOKEN";
        }
        if (containsAny(candidate, "MFA", "TOTP", "OTP")) {
            return "MFA_ONLY";
        }
        if ("UNKNOWN".equals(candidate) || containsAny(candidate, "ANONYMOUS", "UNAUTHENTICATED")) {
            return "UNKNOWN";
        }
        return null;
    }

    private static boolean containsAny(String candidate, String... fragments) {
        for (String fragment : fragments) {
            if (candidate.contains(fragment)) {
                return true;
            }
        }
        return false;
    }
}
