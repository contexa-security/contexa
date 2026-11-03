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

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Ownership design S-2: the verification-only step-up of HOST_OWNED. */
class HostOwnedStepUpServiceTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final ChallengeResolution resolution = mock(ChallengeResolution.class);
    private final UserRepository users = mock(UserRepository.class);
    private final OneTimeTokenService oneTimeTokens = mock(OneTimeTokenService.class);
    private final EmailService email = mock(EmailService.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/step-up");
    private final Authentication alice = new TestingAuthenticationToken("alice", null, "ROLE_USER");
    private HostOwnedStepUpService service;

    @BeforeEach
    void setUp() {
        service = new HostOwnedStepUpService(actions, resolution, users, "shadow.contexa.local",
                new InMemoryStepUpOptionsStore(), oneTimeTokens, email, null, null, null, null,
                "/login?prompt=login");
        when(email.isMailSenderConfigured()).thenReturn(true);
        when(resolution.releaseChallenge(anyString(), any(), any(), any())).thenReturn(true);
    }

    private Users bridged(String username, String address) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(42L);
        when(user.getUsername()).thenReturn(username);
        when(user.getEmail()).thenReturn(address);
        when(users.findByExternalSubjectIdAndBridgeManagedTrue("alice")).thenReturn(List.of(user));
        return user;
    }

    @Test
    @DisplayName("a CHALLENGE in force is what the step-up resolves; the application's re-login link is offered")
    void aChallengeInForceIsResolved() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        bridged("brg_alice", "alice@corp.example");

        HostOwnedStepUpService.Situation situation = service.situation(request, alice);

        assertThat(situation.purpose()).isEqualTo(HostOwnedStepUpService.Purpose.CHALLENGE);
        assertThat(situation.oneTimeCode()).isTrue();
        assertThat(situation.passkeyRegistrable()).as("no registration under a restriction").isFalse();
        assertThat(situation.reauthenticationUrl()).isEqualTo("/login?prompt=login");
    }

    @Test
    @DisplayName("a BLOCK is resolved only when an administrator let the user release it by MFA")
    void aBlockOnlyWithReleaseByMfa() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.BLOCK);
        bridged("brg_alice", "alice@corp.example");

        assertThat(service.situation(request, alice).purpose()).isNull();
        when(actions.isBlockMfaPending("alice")).thenReturn(true);
        assertThat(service.situation(request, alice).purpose()).isEqualTo(HostOwnedStepUpService.Purpose.BLOCK);
    }

    @Test
    @DisplayName("only the bridge's copy of the application user is used, never a Contexa account of the same name")
    void onlyTheBridgedUser() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(users.findByExternalSubjectIdAndBridgeManagedTrue("alice")).thenReturn(List.of());

        HostOwnedStepUpService.Situation situation = service.situation(request, alice);

        assertThat(situation.user()).isNull();
        assertThat(situation.oneTimeCode()).isFalse();
        assertThat(situation.passkey()).isFalse();
        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.UNAVAILABLE);
        verifyNoInteractions(oneTimeTokens);
    }

    @Test
    @DisplayName("no code goes to the bridge's made-up address")
    void noCodeToAMadeUpAddress() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        bridged("brg_alice", "brg_alice@shadow.contexa.local");

        assertThat(service.situation(request, alice).oneTimeCode()).isFalse();
        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.UNAVAILABLE);
        verifyNoInteractions(oneTimeTokens);
    }

    @Test
    @DisplayName("a code of another user does not resolve the step-up; the user's own code does, without a session")
    void onlyTheUsersOwnCode() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        bridged("brg_alice", "alice@corp.example");
        when(oneTimeTokens.consume(any())).thenReturn(new DefaultOneTimeToken("123456", "step-up:7", Instant.now()));

        assertThat(service.verifyCode(request, alice, "123456")).isFalse();
        verify(resolution, never()).releaseChallenge(anyString(), any(), any(), any());

        when(oneTimeTokens.consume(any())).thenReturn(new DefaultOneTimeToken("654321", "step-up:42", Instant.now()));
        assertThat(service.verifyCode(request, alice, "654321")).isTrue();
        verify(resolution).releaseChallenge(eq("alice"), any(), eq(request), any());
        verify(resolution).markMfaVerified(eq("alice"), any());
        assertThat(request.getSession(false)).as("the application's session is not touched").isNull();
    }

    @Test
    @DisplayName("a BLOCK released by MFA is released through the shared resolution")
    void aBlockReleasedByMfa() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.BLOCK);
        when(actions.isBlockMfaPending("alice")).thenReturn(true);
        bridged("brg_alice", "alice@corp.example");
        when(oneTimeTokens.consume(any())).thenReturn(new DefaultOneTimeToken("654321", "step-up:42", Instant.now()));

        assertThat(service.verifyCode(request, alice, "654321")).isTrue();
        verify(resolution).releaseBlockByMfa("alice");
        verify(resolution, never()).releaseChallenge(anyString(), any(), any(), any());
    }

    @Test
    @DisplayName("the application's own MFA re-authentication after the CHALLENGE releases it; an earlier one does not")
    void theApplicationsReauthentication() {
        Instant challengedAt = Instant.parse("2026-11-03T10:00:00Z");
        when(actions.getAnalysisData("alice")).thenReturn(new ZeroTrustActionRepository.ZeroTrustAnalysisData(
                "CHALLENGE", 0.6, 0.8, null, 1, challengedAt.toString(), null, null, "r-1", null, null));

        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(true, challengedAt.minusSeconds(60)));
        assertThat(service.resolvedByHostReauthentication(request, alice, "alice")).isFalse();

        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(false, challengedAt.plusSeconds(60)));
        assertThat(service.resolvedByHostReauthentication(request, alice, "alice")).as("one factor is not MFA").isFalse();
        verify(resolution, never()).releaseChallenge(anyString(), any(), any(), any());

        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(true, challengedAt.plusSeconds(60)));
        assertThat(service.resolvedByHostReauthentication(request, alice, "alice")).isTrue();
        verify(resolution).releaseChallenge(eq("alice"), any(), eq(request), any());
        verify(resolution).markMfaVerified("alice", challengedAt.plusSeconds(60));
    }

    /**
     * Exception test E-S8 (2026-11-03): fifteen code requests in a row under a CHALLENGE sent fifteen mails, so a
     * session under a CHALLENGE could flood the user's mailbox.
     */
    @Test
    @DisplayName("a second code request within the interval sends nothing; a failed send frees the interval")
    void theMailboxIsNotFlooded() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        bridged("brg_alice", "alice@corp.example");
        when(oneTimeTokens.generate(any())).thenReturn(new DefaultOneTimeToken("123456", "step-up:42", Instant.now()));

        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);
        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.TOO_SOON);
        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.TOO_SOON);

        verify(oneTimeTokens, times(1)).generate(any());
        verify(email, times(1)).sendHtmlMessage(eq("alice@corp.example"), anyString(), anyString());
    }

    @Test
    @DisplayName("a code that could not be mailed does not hold the user back for the interval")
    void aFailedSendFreesTheInterval() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        bridged("brg_alice", "alice@corp.example");
        when(oneTimeTokens.generate(any())).thenReturn(new DefaultOneTimeToken("123456", "step-up:42", Instant.now()));
        doThrow(new IllegalStateException("mail server down")).doNothing().when(email)
                .sendHtmlMessage(anyString(), anyString(), anyString());

        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.UNAVAILABLE);
        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);
    }

    /**
     * Exception test E-S14 (2026-11-03): eight requests at once with one valid code all passed, because the token
     * service reads the code before it deletes it, so each of them found it. A code is spent once.
     */
    @Test
    @DisplayName("a code the token service hands out twice (a race) resolves the step-up once")
    void aCodeIsSpentOnce() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        bridged("brg_alice", "alice@corp.example");
        when(oneTimeTokens.consume(any())).thenReturn(new DefaultOneTimeToken("654321", "step-up:42", Instant.now()));

        assertThat(service.verifyCode(request, alice, "654321")).isTrue();
        assertThat(service.verifyCode(request, alice, "654321")).isFalse();
        assertThat(service.verifyCode(request, alice, " 654321 ")).as("spaces do not make it another code").isFalse();

        verify(resolution, times(1)).releaseChallenge(eq("alice"), any(), eq(request), any());
    }

    @Test
    @DisplayName("an agent answers no factor made for people")
    void noStepUpForAnAgent() {
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP,
                new DelegationStamp("alice", "agent-1", true, null, null, null, null, null, null, null, null, null,
                        null));

        assertThat(service.situation(request, alice)).isNull();
    }

    private static AuthenticationStamp stamp(boolean mfa, Instant at) {
        return new AuthenticationStamp("alice", "Alice", "USER", true, "OIDC", "IDP", "AAL2", mfa, at, null,
                List.of(), null);
    }
}
