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
package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent/bridge-v2-B5-2-B5-3-설계안.md 2, ContexaBridge.signedIn: a user the application names at its sign-in becomes
 * Contexa's identity of the request as a user it puts in the request attribute does, and the sign-in waits for the copy of
 * the user, which writes the time of the sign-in.
 */
@DisplayName("bridge v2 로그인 알림: 레거시가 알린 사용자가 요청 신원이 되고 사본 동기화를 로그인으로 기다린다")
class BridgeResolutionFilterSignedInTest {

    private static final Instant LOGIN_AT = Instant.parse("2026-11-26T01:00:00Z");
    private static final BridgeUserMirrorSyncResult KIM_COPY =
            new BridgeUserMirrorSyncResult(7L, "brg_kim01", "kim01", "key-kim01", true, true, true, false);

    private final BridgeUserMirrorSyncService sync = mock(BridgeUserMirrorSyncService.class);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("SANDBOX: 알린 사용자가 요청 신원·스탬프가 되고, 사본 동기화를 로그인으로 기다리며, 앱 보안 문맥은 비어 있다")
    void theNamedUserBecomesTheIdentityAndItsCopyIsWaitedForAsASignIn() {
        when(sync.sync(any(), any(), any(), anyBoolean())).thenReturn(KIM_COPY);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/login");

        ContexaIdentity identity = filter(properties("SANDBOX")).signedIn(request, ContexaSubject.of("kim01",
                "kim01@seum.example").authentication(ContexaAuthentication.of("PASSWORD").mfa(false)
                .authenticatedAt(LOGIN_AT)).build());

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.RESOLVED);
        assertThat(ContexaIdentity.current(request)).isSameAs(identity);
        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.REQUEST_ATTRIBUTE);
        assertThat(((Authentication) request.getAttribute(BridgeRequestAttributes.IDENTITY)).getName()).isEqualTo("kim01");
        AuthenticationStamp stamp = (AuthenticationStamp) request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
        assertThat(stamp.principalId()).isEqualTo("kim01");
        assertThat(stamp.authenticationTime()).isEqualTo(LOGIN_AT);
        verify(sync).sync(argThat(written -> "kim01".equals(written.principalId())), any(), any(), eq(true));
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("아이디 규칙을 어긴 사용자는 신원이 되지 않고 사본도 동기화하지 않는다")
    void aUserIdThatBreaksItsRulesMakesNoIdentityAndNoCopy() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/login");

        ContexaIdentity identity = filter(properties("SANDBOX")).signedIn(request, ContexaSubject.of("kim\u000001",
                "kim01@seum.example").build());

        assertThat(identity.isResolved()).isFalse();
        assertThat(request.getAttribute(BridgeRequestAttributes.IDENTITY)).isNull();
        verify(sync, never()).sync(any(), any(), any(), anyBoolean());
    }

    private static BridgeProperties properties(String mode) {
        BridgeProperties properties = new BridgeProperties();
        properties.setEnvironment(new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, mode));
        return properties;
    }

    private BridgeResolutionFilter filter(BridgeProperties properties) {
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(),
                List.of(),
                List.of(),
                new BridgeCoverageEvaluator(),
                null,
                new BridgeRuntimeSupport(properties, sync),
                null,
                new IdentityResolution(IdentityResolution.Settings.of(properties), null, null, null,
                        IdentityResolution.Accounts.NONE, new IdentityDiagnostics()));
    }
}
