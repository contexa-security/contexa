/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.mfa.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

class MfaPasskeyRegistrationIntentTest {

    @Test
    @DisplayName("consume returns true once for the MFA session the intent was recorded for")
    void consumeIsOneTimeAndBoundToMfaSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        MfaPasskeyRegistrationIntent.record(request, "mfa-1");

        assertThat(request.getSession(false)).isNotNull();
        assertThat(MfaPasskeyRegistrationIntent.consume(request, "mfa-1")).isTrue();
        assertThat(MfaPasskeyRegistrationIntent.consume(request, "mfa-1")).isFalse();
    }

    @Test
    @DisplayName("An intent of another MFA session is not honored and is removed")
    void staleIntentIsDiscarded() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPasskeyRegistrationIntent.record(request, "mfa-old");

        assertThat(MfaPasskeyRegistrationIntent.consume(request, "mfa-new")).isFalse();
        assertThat(request.getSession(false).getAttribute(MfaPasskeyRegistrationIntent.SESSION_ATTRIBUTE)).isNull();
        assertThat(MfaPasskeyRegistrationIntent.consume(request, null)).isFalse();
    }

    @Test
    @DisplayName("consume tolerates missing and invalidated sessions")
    void consumeToleratesMissingSession() {
        assertThat(MfaPasskeyRegistrationIntent.consume(new MockHttpServletRequest(), "mfa-1")).isFalse();

        MockHttpServletRequest invalidated = new MockHttpServletRequest();
        MfaPasskeyRegistrationIntent.record(invalidated, "mfa-1");
        invalidated.getSession(false).invalidate();
        assertThatCode(() -> MfaPasskeyRegistrationIntent.consume(invalidated, "mfa-1")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Intent and return URL survive a new session that migrates only Spring Security attributes")
    void attributesSurviveSessionFixationProtection() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPasskeyRegistrationIntent.record(request, "mfa-1");
        MfaPasskeyRegistrationIntent.storeReturnUrl(request, "/orders");

        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        strategy.setMigrateSessionAttributes(false);
        strategy.onAuthentication(UsernamePasswordAuthenticationToken.authenticated("user", null, List.of()),
                request, new MockHttpServletResponse());

        assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isEqualTo("/orders");
        assertThat(MfaPasskeyRegistrationIntent.consume(request, "mfa-1")).isTrue();
    }

    @Test
    @DisplayName("Return URL is stored, read and cleared")
    void returnUrlRoundTrip() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        MfaPasskeyRegistrationIntent.storeReturnUrl(request, "/app/orders?id=42");

        assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isEqualTo("/app/orders?id=42");
        MfaPasskeyRegistrationIntent.clearReturnUrl(request);
        assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)", " "})
    @DisplayName("Return URLs outside the application are not stored")
    void foreignReturnUrlsAreRejected(String returnUrl) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPasskeyRegistrationIntent.storeReturnUrl(request, "/home");

        MfaPasskeyRegistrationIntent.storeReturnUrl(request, returnUrl);

        assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isNull();
    }
}
