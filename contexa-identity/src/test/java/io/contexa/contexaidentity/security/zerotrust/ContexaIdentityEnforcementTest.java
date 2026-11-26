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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: Contexa's enforcement filters behind the application's chain decide a
 * request of a user the bridge resolved for Contexa alone (a legacy application that signs its users in without Spring
 * Security), under the same user key, and leave the application's security context as it is.
 */
@DisplayName("집행 필터는 bridge가 해석한 Contexa 신원으로 판정한다(R-10)")
class ContexaIdentityEnforcementTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final SandboxStepUp stepUp = mock(SandboxStepUp.class);
    private final Authentication alice = signedIn("alice");

    @BeforeEach
    void setUp() {
        when(stepUp.stepUpUrl(any(HttpServletRequest.class))).thenReturn("/contexa/step-up");
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("사용자 단위 CHALLENGE는 Spring 인증이 없는 레거시 사용자의 요청도 멈춘다")
    void aStoredChallengeStopsTheBridgedUser() throws Exception {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        ZeroTrustChallengeFilter filter = new ZeroTrustChallengeFilter(mock(ChallengeMfaInitializer.class),
                responseWriter, mock(AuthUrlProvider.class), mock(MfaSessionRepository.class),
                mock(MfaStateMachineIntegrator.class), mock(DistributedLockService.class),
                mock(MfaFlowUrlRegistry.class), actions);
        filter.setSandboxStepUp(stepUp);
        MockHttpServletRequest request = apiRequest("/orders");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).as("the request was stopped").isNull();
        verify(responseWriter).writeErrorResponse(any(), eq(401), eq("MFA_CHALLENGE_REQUIRED"), anyString(),
                anyString(), anyMap());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("사용자 단위 BLOCK은 Spring 인증이 없는 레거시 사용자의 요청도 막는다")
    void aStoredBlockStopsTheBridgedUser() throws Exception {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.BLOCK);
        when(actions.isBlockMfaPending("alice")).thenReturn(false);
        ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(actions, responseWriter,
                mock(IBlockedUserRecorder.class), mock(ChallengeMfaInitializer.class), mock(AuthUrlProvider.class),
                mock(BlockingSignalBroadcaster.class), 2);
        filter.setSandboxStepUp(stepUp);
        MockHttpServletRequest request = apiRequest("/orders");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).as("the request was stopped").isNull();
        verify(responseWriter).writeErrorResponse(any(), eq(403), eq("ACCOUNT_BLOCKED"), anyString(), anyString(),
                anyMap());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Contexa 사용자 경로는 bridge 신원을 들이고, 그 처리기에는 요청의 사용자로 보인다")
    void theUsersPagesTakeTheBridgedUser() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/zero-trust/blocked");
        request.setAttribute(BridgeRequestAttributes.IDENTITY, alice);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new SandboxUserPathGuard().doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isNotNull();
        assertThat(((HttpServletRequest) chain.getRequest()).getUserPrincipal()).isSameAs(alice);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("신원이 없는 요청은 지금처럼 판정 없이 지나간다")
    void anUnresolvedRequestPassesAsBefore() throws Exception {
        ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(actions, responseWriter,
                mock(IBlockedUserRecorder.class), mock(ChallengeMfaInitializer.class), mock(AuthUrlProvider.class),
                mock(BlockingSignalBroadcaster.class), 2);
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    private MockHttpServletRequest apiRequest(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.addHeader("Accept", "application/json");
        request.setAttribute(BridgeRequestAttributes.IDENTITY, alice);
        return request;
    }

    private static Authentication signedIn(String name) {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken(name, null, "ROLE_USER");
        authentication.setAuthenticated(true);
        return authentication;
    }
}
