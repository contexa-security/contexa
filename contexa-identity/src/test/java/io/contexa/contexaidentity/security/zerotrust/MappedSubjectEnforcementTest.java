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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * bridge v2 (B4): an application that signs its users in with Spring Security under a principal object of its own names
 * the user with a {@code ContexaSubjectMapper}. Contexa's enforcement filters key the request's decisions by the user the
 * mapper named ({@link ContexaIdentity#userId}), never by the text of the application's object, which Contexa does not
 * read.
 */
@DisplayName("집행 필터는 매퍼가 이름 지은 사용자로 판정 키를 쓴다(bridge v2)")
class MappedSubjectEnforcementTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final IBlockedUserRecorder blockedUsers = mock(IBlockedUserRecorder.class);
    private final SandboxStepUp stepUp = mock(SandboxStepUp.class);
    private final LegacyMember member = new LegacyMember("kim01", "secret-hash");
    private final Authentication application = UsernamePasswordAuthenticationToken.authenticated(member, null,
            AuthorityUtils.createAuthorityList("ROLE_USER"));

    @BeforeEach
    void setUp() {
        when(stepUp.stepUpUrl(any(HttpServletRequest.class))).thenReturn("/contexa/step-up");
        SecurityContextHolder.getContext().setAuthentication(application);
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("매퍼가 이름 지은 사용자의 BLOCK은 앱 고유 principal 객체로 로그인한 사용자의 요청을 막는다")
    void aStoredBlockOfTheMappedUserStopsTheRequest() throws Exception {
        when(actions.getCurrentAction(eq("kim01"), any())).thenReturn(ZeroTrustAction.BLOCK);
        MockHttpServletRequest request = mapped(apiRequest());
        MockFilterChain chain = new MockFilterChain();

        accessControl().doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).as("the request was stopped").isNull();
        verify(responseWriter).writeErrorResponse(any(), eq(403), eq("ACCOUNT_BLOCKED"), anyString(), anyString(),
                anyMap());
        verify(actions, never()).getCurrentAction(eq(member.toString()), any());
        verify(actions, never()).getCurrentAction(eq("unknown"), any());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(application);
    }

    @Test
    @DisplayName("기한이 지난 ESCALATE를 BLOCK으로 올리면 차단 기록의 사용자와 이름은 매퍼가 이름 지은 ID다")
    void anEscalatePromotedToBlockRecordsTheMappedUser() throws Exception {
        when(actions.getCurrentAction(eq("kim01"), any())).thenReturn(ZeroTrustAction.ESCALATE);
        MockHttpServletRequest request = mapped(apiRequest());

        accessControl().doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(actions).saveAction(eq("kim01"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(blockedUsers).recordBlock(anyString(), eq("kim01"), eq("kim01"), eq("BLOCK"), anyString(), any(), any());
        verify(responseWriter).writeErrorResponse(any(), eq(403), eq("ACCOUNT_BLOCKED"), anyString(), anyString(),
                anyMap());
    }

    @Test
    @DisplayName("매퍼가 이름 지은 사용자의 CHALLENGE는 그 ID로 읽혀 앱 고유 principal 객체로 로그인한 사용자의 요청을 멈춘다")
    void aStoredChallengeOfTheMappedUserStopsTheRequest() throws Exception {
        when(actions.getCurrentAction(eq("kim01"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        ZeroTrustChallengeFilter filter = new ZeroTrustChallengeFilter(mock(ChallengeMfaInitializer.class),
                responseWriter, mock(AuthUrlProvider.class), mock(MfaSessionRepository.class),
                mock(MfaStateMachineIntegrator.class), mock(DistributedLockService.class),
                mock(MfaFlowUrlRegistry.class), actions);
        filter.setSandboxStepUp(stepUp);
        MockHttpServletRequest request = mapped(apiRequest());
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).as("the request was stopped").isNull();
        verify(stepUp).resolvedByHostReauthentication(any(HttpServletRequest.class), eq(application), eq("kim01"));
        verify(responseWriter).writeErrorResponse(any(), eq(401), eq("MFA_CHALLENGE_REQUIRED"), anyString(),
                anyString(), anyMap());
        verify(actions, never()).getCurrentAction(eq("unknown"), any());
    }

    private ZeroTrustAccessControlFilter accessControl() {
        ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(actions, responseWriter, blockedUsers,
                mock(ChallengeMfaInitializer.class), mock(AuthUrlProvider.class), mock(BlockingSignalBroadcaster.class),
                2);
        filter.setSandboxStepUp(stepUp);
        return filter;
    }

    private static MockHttpServletRequest apiRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader("Accept", "application/json");
        return request;
    }

    /** The identity the bridge filter makes for the request, with the application's mapper. */
    private MockHttpServletRequest mapped(MockHttpServletRequest request) {
        ContexaSubjectMapper mapper = authentication -> authentication.getPrincipal() instanceof LegacyMember legacy
                ? Optional.of(ContexaSubject.of(legacy.empNo(), legacy.empNo() + "@seum.example").build())
                : Optional.empty();
        ContexaIdentity identity = new IdentityResolution(IdentityResolution.Settings.defaults(), null, mapper, null,
                IdentityResolution.Accounts.NONE, new IdentityDiagnostics()).resolve(request, application);
        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(ContexaIdentity.subjectId(application)).as("Contexa reads no field of the application's object")
                .isNull();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
        return request;
    }

    /** An application's own principal object, none of the kinds Spring Security names a user by. */
    record LegacyMember(String empNo, String passwordHash) {
    }
}
