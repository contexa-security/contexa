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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Principal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The application's own re-authentication answers a CHALLENGE only where the application said where it re-authenticates
 * ({@code contexa.bridge.step-up.reauthentication-url}). Elsewhere what the bridge reads as a completed MFA is a value of
 * the principal Contexa cannot vouch for: a flag that MFA is switched on, with the time of the last password sign-in.
 */
class HostReauthenticationNeedsItsUrlTest {

    /**
     * A principal whose mfa flag says MFA is switched on, and whose loginTime moves with each password sign-in. It names
     * its user as a principal does, the name every decision of the user is keyed by (R-10).
     */
    public static class AppUser implements Principal {
        private final boolean mfa;
        private final Instant loginTime;

        AppUser(boolean mfa, Instant loginTime) {
            this.mfa = mfa;
            this.loginTime = loginTime;
        }

        @Override
        public String getName() {
            return "alice";
        }

        public String getUsername() {
            return "alice";
        }

        public boolean isMfa() {
            return mfa;
        }

        public Instant getLoginTime() {
            return loginTime;
        }
    }

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final ChallengeResolution resolution = new ChallengeResolution(actions, null, null, null, null, null, null);
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private SandboxStepUpService stepUp(String reauthenticationUrl) {
        return new SandboxStepUpService(actions, resolution, mock(UserRepository.class), "shadow.contexa.local",
                new InMemoryStepUpOptionsStore(), null, null, null, null, null, null, reauthenticationUrl, 5);
    }

    private Authentication signedInAgain(AppUser user) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AuthenticationStamp stamp = new SecurityContextAuthenticationStampResolver().resolve(request,
                new RequestContextSnapshot("/orders", "GET", "203.0.113.1", "ua", "s-1", "r-1", "/orders", null, false,
                        Instant.now()), new BridgeProperties()).orElseThrow();
        assertThat(stamp.principalId()).isEqualTo("alice");
        assertThat(stamp.mfaCompleted()).isEqualTo(user.isMfa());
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp);
        return authentication;
    }

    private String challenged() throws InterruptedException {
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        String context = SessionFingerprintUtil.generateContextBindingHash(request);
        assertThat(actions.getCurrentAction("alice", context)).isEqualTo(ZeroTrustAction.CHALLENGE);
        Thread.sleep(5);
        return context;
    }

    @Test
    @DisplayName("without the application's re-authentication URL a password sign-in with a standing mfa flag releases nothing")
    void withoutTheUrl() throws Exception {
        String context = challenged();
        Authentication again = signedInAgain(new AppUser(true, Instant.now().plusSeconds(1)));

        assertThat(stepUp(null).resolvedByHostReauthentication(request, again, "alice")).isFalse();
        assertThat(stepUp(" ").resolvedByHostReauthentication(request, again, "alice")).isFalse();

        assertThat(actions.getCurrentAction("alice", context)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("an application that names its re-authentication has its MFA after the CHALLENGE release it")
    void withTheUrl() throws Exception {
        String context = challenged();
        Authentication again = signedInAgain(new AppUser(true, Instant.now().plusSeconds(1)));

        assertThat(stepUp("/login?prompt=login").resolvedByHostReauthentication(request, again, "alice")).isTrue();

        assertThat(actions.getCurrentAction("alice", context)).isNotEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("an application that names its re-authentication is still answered by a completed MFA only")
    void withTheUrlASignInOfOneFactor() throws Exception {
        String context = challenged();
        Authentication again = signedInAgain(new AppUser(false, Instant.now().plusSeconds(1)));

        assertThat(stepUp("/login?prompt=login").resolvedByHostReauthentication(request, again, "alice")).isFalse();

        assertThat(actions.getCurrentAction("alice", context)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    /** A principal that keeps the time of its sign-in as legacy systems do: yyyyMMddHHmmss digits. */
    public static class LegacyAppUser {
        public String getUsername() {
            return "alice";
        }

        public boolean isMfa() {
            return true;
        }

        public String getLoginTime() {
            return "20261125103000";
        }
    }

    @Test
    @DisplayName("레거시 객체를 principal로 둔 인증은 읽지 않으므로 그 객체가 말하는 로그인 시각으로 CHALLENGE를 풀지 않는다")
    void withTheUrlASignInTimeReadAheadOfTheClock() throws Exception {
        String context = challenged();
        Authentication again = new UsernamePasswordAuthenticationToken(new LegacyAppUser(), null, List.of());
        SecurityContextHolder.getContext().setAuthentication(again);
        Optional<AuthenticationStamp> stamp = new SecurityContextAuthenticationStampResolver().resolve(request,
                new RequestContextSnapshot("/orders", "GET", "203.0.113.1", "ua", "s-1", "r-1", "/orders", null, false,
                        Instant.now()), new BridgeProperties());

        assertThat(stamp).as("a principal of the application's own type is not read (bridge v2 standard 3.2)").isEmpty();
        assertThat(stepUp("/login?prompt=login").resolvedByHostReauthentication(request, again, "alice")).isFalse();

        assertThat(actions.getCurrentAction("alice", context)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("다른 해석기가 만든 도장에 미래 인증 시각이 있어도 CHALLENGE를 풀지 않는다")
    void withTheUrlAStampOfAnotherResolverAheadOfTheClock() throws Exception {
        String context = challenged();
        Authentication again = new UsernamePasswordAuthenticationToken("alice", null, List.of());
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, new AuthenticationStamp("alice", "alice",
                "USER", true, "PASSWORD_OTP", "SESSION", null, true, Instant.now().plusSeconds(3_600), "s-1",
                List.of(), Map.of()));

        assertThat(stepUp("/login?prompt=login").resolvedByHostReauthentication(request, again, "alice")).isFalse();

        assertThat(actions.getCurrentAction("alice", context)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }
}
