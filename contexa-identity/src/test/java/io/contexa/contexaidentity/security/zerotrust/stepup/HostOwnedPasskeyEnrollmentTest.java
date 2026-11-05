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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-13 (PR-60): a passkey is what answers a CHALLENGE, so whoever holds only the password must not be able to register
 * one. A first passkey needs the user's mail code or the application's own fresh re-authentication.
 */
class HostOwnedPasskeyEnrollmentTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final ChallengeResolution resolution = mock(ChallengeResolution.class);
    private final UserRepository users = mock(UserRepository.class);
    private final OneTimeTokenService oneTimeTokens = mock(OneTimeTokenService.class);
    private final EmailService email = mock(EmailService.class);
    private final WebAuthnRelyingPartyOperations relyingParty = mock(WebAuthnRelyingPartyOperations.class);
    private final PublicKeyCredentialUserEntityRepository entities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository credentials = mock(UserCredentialRepository.class);
    private final PasskeyCreationOptionsCodec codec = mock(PasskeyCreationOptionsCodec.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/step-up/passkey/register/options");
    private final Authentication alice = new TestingAuthenticationToken("alice", null, "ROLE_USER");
    private HostOwnedStepUpService service;

    @BeforeEach
    void setUp() {
        service = new HostOwnedStepUpService(actions, resolution, users, "shadow.contexa.local",
                new InMemoryStepUpOptionsStore(), oneTimeTokens, email, relyingParty, entities, credentials, codec, null, 5);
        request.setRemoteAddr("198.51.100.1");
        when(email.isMailSenderConfigured()).thenReturn(true);
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(42L);
        when(user.getUsername()).thenReturn("brg_alice");
        when(user.getEmail()).thenReturn("alice@corp.example");
        when(users.findByExternalSubjectIdAndBridgeManagedTrue("alice")).thenReturn(List.of(user));
        when(oneTimeTokens.consume(any())).thenReturn(new DefaultOneTimeToken("654321", "step-up:42", Instant.now()));
    }

    private void decided(ZeroTrustAction action) {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(action);
    }

    private static AuthenticationStamp signIn(boolean mfa, Instant at) {
        return new AuthenticationStamp("alice", "Alice", "USER", true, "OIDC", "IDP", "AAL2", mfa, at, null,
                List.of(), null);
    }

    @Test
    @DisplayName("the stolen password before the first decision: the options of a registration are refused")
    void beforeTheFirstDecision() {
        decided(ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(service.registrationOptions(request, alice)).isNull();
        verify(relyingParty, never()).createPublicKeyCredentialCreationOptions(any());
    }

    @Test
    @DisplayName("an ALLOW proves nothing: the password alone still registers nothing")
    void anAllowIsNoProof() {
        decided(ZeroTrustAction.ALLOW);

        assertThat(service.situation(request, alice).passkeyEnrollable()).isTrue();
        assertThat(service.situation(request, alice).passkeyRegistrable()).isFalse();
        assertThat(service.registrationOptions(request, alice)).isNull();
    }

    @Test
    @DisplayName("the code mailed to the user's own address opens the registration for this session")
    void theMailCodeOpensIt() {
        decided(ZeroTrustAction.ALLOW);
        when(oneTimeTokens.generate(any())).thenReturn(new DefaultOneTimeToken("654321", "step-up:42", Instant.now()));

        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);
        assertThat(service.verifyCode(request, alice, "654321")).isTrue();

        assertThat(service.situation(request, alice).passkeyRegistrable()).isTrue();
        service.registrationOptions(request, alice);
        verify(relyingParty).createPublicKeyCredentialCreationOptions(any());
        verify(resolution, never()).releaseChallenge(anyString(), any(), any(), any());
    }

    @Test
    @DisplayName("the proof stays with the session that gave it")
    void theProofStaysInItsSession() {
        decided(ZeroTrustAction.ALLOW);
        service.verifyCode(request, alice, "654321");

        MockHttpServletRequest other = new MockHttpServletRequest("POST", "/contexa/step-up/passkey/register/options");
        other.setRemoteAddr("203.0.113.9");

        assertThat(service.situation(other, alice).passkeyRegistrable()).isFalse();
    }

    @Test
    @DisplayName("a wrong code proves nothing")
    void aWrongCode() {
        decided(ZeroTrustAction.ALLOW);
        when(oneTimeTokens.consume(any())).thenReturn(null);

        assertThat(service.verifyCode(request, alice, "000000")).isFalse();

        assertThat(service.situation(request, alice).passkeyRegistrable()).isFalse();
    }

    @Test
    @DisplayName("a code passed under a CHALLENGE offers the passkey at once, once the CHALLENGE is answered")
    void aCodeUnderAChallengeOffersThePasskey() {
        decided(ZeroTrustAction.CHALLENGE);
        when(resolution.releaseChallenge(anyString(), any(), any(), any())).thenReturn(true);

        assertThat(service.verifyCode(request, alice, "654321")).isTrue();
        decided(ZeroTrustAction.ALLOW);

        assertThat(service.situation(request, alice).passkeyRegistrable()).isTrue();
    }

    @Test
    @DisplayName("under a CHALLENGE no proof opens the registration")
    void noRegistrationUnderAChallenge() {
        decided(ZeroTrustAction.ALLOW);
        service.verifyCode(request, alice, "654321");
        decided(ZeroTrustAction.CHALLENGE);

        assertThat(service.situation(request, alice).passkeyRegistrable()).isFalse();
        assertThat(service.registrationOptions(request, alice)).isNull();
    }

    @Test
    @DisplayName("the application's own MFA sign-in moments ago is proof; an old one and a sign-in of one factor are not")
    void theApplicationsReauthentication() {
        decided(ZeroTrustAction.ALLOW);

        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, signIn(true, Instant.now().minusSeconds(30)));
        assertThat(service.situation(request, alice).passkeyRegistrable()).isTrue();

        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, signIn(true, Instant.now().minusSeconds(3600)));
        assertThat(service.situation(request, alice).passkeyRegistrable()).isFalse();

        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, signIn(false, Instant.now().minusSeconds(30)));
        assertThat(service.situation(request, alice).passkeyRegistrable()).isFalse();
    }
}
