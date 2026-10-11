package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.AuthenticationMethodReferences;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Login methods and their RFC 8176 references are one vocabulary in both directions (W1-4).
 */
class AuthenticationMethodReferencesTest {

    @Test
    void aMultiFactorLoginIsWrittenWithEachReferenceAndMfa() {
        List<String> methods = List.of(AuthenticationMethodReferences.PASSWORD, AuthenticationMethodReferences.ONE_TIME_CODE);

        assertThat(AuthenticationMethodReferences.referencesOf(methods)).containsExactly("pwd", "otp", "mfa");
        assertThat(AuthenticationMethodReferences.methodName(methods)).isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(AuthenticationMethodReferences.assuranceOf(methods)).isEqualTo("AAL2");
    }

    @Test
    void aSingleMethodLoginIsNotMultiFactor() {
        List<String> methods = List.of(AuthenticationMethodReferences.PASSKEY);

        assertThat(AuthenticationMethodReferences.referencesOf(methods)).containsExactly("pop");
        assertThat(AuthenticationMethodReferences.assuranceOf(methods)).isEqualTo("AAL1");
        assertThat(AuthenticationMethodReferences.multiFactor(List.of("pop"))).isFalse();
    }

    @Test
    void theSameLoginHasOneNameWhateverTheOrder() {
        assertThat(AuthenticationMethodReferences.methodName(List.of("ONE_TIME_CODE", "PASSWORD")))
                .isEqualTo("PASSWORD+ONE_TIME_CODE");
        assertThat(AuthenticationMethodReferences.methodsOf(List.of("otp", "pwd"))).containsExactly("PASSWORD", "ONE_TIME_CODE");
        assertThat(AuthenticationMethodReferences.referencesOf(List.of("ONE_TIME_CODE", "PASSWORD")))
                .containsExactly("pwd", "otp", "mfa");
    }

    @Test
    void referencesReadBackToTheSameMethods() {
        assertThat(AuthenticationMethodReferences.methodsOf(List.of("pwd", "otp", "mfa")))
                .containsExactly("PASSWORD", "ONE_TIME_CODE");
        assertThat(AuthenticationMethodReferences.multiFactor(List.of("pwd", "otp"))).isTrue();
        assertThat(AuthenticationMethodReferences.multiFactor(List.of("mfa"))).isTrue();
        assertThat(AuthenticationMethodReferences.multiFactor(List.of())).isNull();
        assertThat(AuthenticationMethodReferences.methodName(AuthenticationMethodReferences.methodsOf(List.of("kba"))))
                .isNull();
    }
}
