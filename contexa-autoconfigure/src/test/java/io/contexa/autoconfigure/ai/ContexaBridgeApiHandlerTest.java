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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridgeResult.Outcome;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.HostSignInEvents;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** docs/agent/bridge-v2-B5-2-B5-3-설계안.md 2: each optional call ends in the state Contexa's own events leave. */
@DisplayName("bridge v2 선택 API 처리기: 로그인·실패·로그아웃·삭제 알림이 Contexa 자신의 처리와 같은 상태로 끝난다")
class ContexaBridgeApiHandlerTest {

    private final BridgeResolutionFilter bridge = mock(BridgeResolutionFilter.class);
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final SecurityContextDataStore securityContext = mock(SecurityContextDataStore.class);
    private final HostSignInEvents signInEvents = new HostSignInEvents();
    private final SessionManagementService sessions = mock(SessionManagementService.class);
    private final ZeroTrustSecurityService zeroTrust = mock(ZeroTrustSecurityService.class);
    private final SessionIdResolver sessionIds = mock(SessionIdResolver.class);
    private final UserEngineStatePurger purger = mock(UserEngineStatePurger.class);
    private final BridgeRuntimeSupport runtime = mock(BridgeRuntimeSupport.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/login");

    @Test
    @DisplayName("SANDBOX 로그인 알림: 알린 사용자가 요청 신원이 되고 로그인 사실이 엔진에 간다")
    void aSignInMakesTheIdentityAndGoesToTheDecisions() {
        ContexaSubject kim = ContexaSubject.of("kim01", "kim01@seum.example").build();
        when(bridge.signedIn(request, kim)).thenReturn(ContexaIdentity.resolved(kim,
                ContexaIdentity.Source.REQUEST_ATTRIBUTE, Set.of(), null));

        assertThat(handler("SANDBOX").signedIn(request, kim).isDone()).isTrue();

        verify(bridge).signedIn(request, kim);
        verify(publisher).publishNamedSignIn(eq(request), argThat(facts ->
                "HOST_SIGN_IN".equals(facts.get("authenticationType"))
                        && ContexaBridgeApiHandler.SIGNED_IN_BY.equals(facts.get("signedInBy"))));
    }

    @Test
    @DisplayName("SANDBOX 로그인 알림: 신원이 되지 못한 사용자는 INVALID이고 엔진에 가지 않는다")
    void aSignInThatMakesNoIdentityIsInvalid() {
        ContexaSubject broken = ContexaSubject.of("kim01", null).build();
        when(bridge.signedIn(request, broken)).thenReturn(ContexaIdentity.unresolved(ContexaIdentity.Outcome.INVALID,
                Set.of()));

        assertThat(handler("SANDBOX").signedIn(request, broken).outcome()).isEqualTo(Outcome.INVALID);

        verify(publisher, never()).publishNamedSignIn(any(), anyMap());
    }

    @Test
    @DisplayName("SANDBOX 실패 알림: 실패 횟수로 기록되고, 이제 실패 사실이 Contexa에 닿는다고 표시된다")
    void aFailedSignInIsCountedAndFailuresAreKnownToReach() {
        assertThat(handler("SANDBOX").signInFailed(request, "kim01").isDone()).isTrue();

        verify(securityContext).recordLoginFailure(eq("kim01"), any(), anyLong());
        assertThat(signInEvents.reaching()).isTrue();
    }

    @Test
    @DisplayName("SANDBOX 로그아웃 알림: 세션 추적을 끝내고 로그아웃 정리를 하며, 한쪽이 실패해도 다른 쪽은 하고 FAILED로 알린다")
    void aSignOutEndsTheTrackingAndTheSignInsStateEachThoughTheOtherFails() {
        String sessionId = request.getSession(true).getId();
        when(sessionIds.resolve(request)).thenReturn("sid-7");

        assertThat(handler("SANDBOX").signedOut(request, "kim01").isDone()).isTrue();
        verify(sessions).endTracking(sessionId);
        verify(zeroTrust).cleanupOnLogout("kim01", "sid-7");

        doThrow(new IllegalStateException("database down")).when(sessions).endTracking(anyString());
        assertThat(handler("SANDBOX").signedOut(request, "kim01").outcome()).isEqualTo(Outcome.FAILED);
        verify(zeroTrust, times(2)).cleanupOnLogout("kim01", "sid-7");
    }

    @Test
    @DisplayName("삭제 알림: 엔진 정리로 사본과 판정 상태를 지우고 요청 경로의 기억을 비우며, 지우지 못한 단계가 있으면 FAILED로 알린다")
    void aDeletionPurgesTheUserAndForgetsTheKeptCopy() {
        when(purger.purge("kim01")).thenReturn(new UserEngineStatePurgeResult("kim01", List.of("decision"), Map.of()));
        when(purger.purge("lee02")).thenReturn(new UserEngineStatePurgeResult("lee02", List.of(),
                Map.of("baseline", "redis down")));

        assertThat(handler("SANDBOX").delete("kim01").isDone()).isTrue();
        verify(runtime).forget("kim01");
        assertThat(handler("SANDBOX").delete("lee02").reason()).contains("baseline");
    }

    @Test
    @DisplayName("FULL: Contexa 주 체인이 앱 사용자를 로그인·로그아웃시키므로 세 알림은 NOT_APPLICABLE이고 아무것도 하지 않는다")
    void inModeFullTheSignInCallsAreNotApplicable() {
        ContexaBridgeApiHandler full = handler("FULL");

        assertThat(full.signedIn(request, ContexaSubject.of("kim01", null).build()).outcome())
                .isEqualTo(Outcome.NOT_APPLICABLE);
        assertThat(full.signInFailed(request, "kim01").outcome()).isEqualTo(Outcome.NOT_APPLICABLE);
        assertThat(full.signedOut(request, "kim01").outcome()).isEqualTo(Outcome.NOT_APPLICABLE);
        verifyNoInteractions(bridge, publisher, securityContext, sessions, zeroTrust);
    }

    private ContexaBridgeApiHandler handler(String mode) {
        BridgeProperties properties = new BridgeProperties();
        properties.setEnvironment(new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, mode));
        return new ContexaBridgeApiHandler(properties, provider(bridge), provider(publisher), provider(securityContext),
                provider(signInEvents), provider(sessions), provider(zeroTrust), provider(sessionIds), provider(purger),
                provider(runtime));
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }
}
