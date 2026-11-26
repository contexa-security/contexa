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
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.lang.Nullable;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * bridge v2 (B4): the step-up of mode SANDBOX answers the user Contexa names the request for
 * ({@link ContexaIdentity#userId}), so a user an application's {@code ContexaSubjectMapper} named under a principal
 * object of the application's own is the one whose decision and copy are read; and the application's re-authentication
 * is read from the sign-in that user's identity states ({@code ContexaSubject.getAuthentication()}) before the bridge's
 * authentication stamp.
 */
@DisplayName("추가 인증은 매퍼가 이름 지은 사용자와 그 신원이 밝힌 로그인 사실을 먼저 쓴다(bridge v2)")
class SandboxStepUpContexaSubjectTest {

    private static final String REAUTHENTICATION_URL = "/login?prompt=login";

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
    private final LegacyMember member = new LegacyMember("kim01", "secret-hash");
    private final Authentication application = UsernamePasswordAuthenticationToken.authenticated(member, null,
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final Users copy = mock(Users.class);
    private SandboxStepUpService service;

    @BeforeEach
    void setUp() {
        service = new SandboxStepUpService(actions, resolution, users, "shadow.contexa.local",
                new InMemoryStepUpOptionsStore(), oneTimeTokens, email, relyingParty, entities, credentials, codec,
                REAUTHENTICATION_URL, 5);
        request.setRemoteAddr("198.51.100.1");
        when(email.isMailSenderConfigured()).thenReturn(true);
        when(copy.getId()).thenReturn(42L);
        when(copy.getUsername()).thenReturn("brg_kim01");
        when(copy.getEmail()).thenReturn("kim01@seum.example");
        when(users.findByExternalSubjectIdAndBridgeManagedTrue("kim01")).thenReturn(List.of(copy));
        SecurityContextHolder.getContext().setAuthentication(application);
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("매퍼가 이름 지은 사용자의 추가 인증은 그 ID로 판정을 읽고 사본을 찾는다")
    void theMappedUsersDecisionAndCopyAreRead() {
        when(actions.getCurrentAction(eq("kim01"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        mapped(null);

        SandboxStepUpService.Situation situation = service.situation(request, application);

        assertThat(situation).isNotNull();
        assertThat(situation.decisionKey()).isEqualTo("kim01");
        assertThat(situation.purpose()).isEqualTo(SandboxStepUpService.Purpose.CHALLENGE);
        assertThat(situation.user()).isSameAs(copy);
        verify(users, never()).findByExternalSubjectIdAndBridgeManagedTrue(member.toString());
    }

    @Test
    @DisplayName("신원이 밝힌 MFA 로그인은 도장보다 먼저 읽혀, 도장이 한 요소 로그인이라 해도 CHALLENGE를 푼다")
    void theIdentitysMfaSignInReleasesTheChallengeBeforeTheStamp() {
        Instant challengedAt = Instant.now().minusSeconds(120);
        Instant signedInAt = Instant.now().minusSeconds(60);
        when(actions.challengeHeldSince("kim01")).thenReturn(challengedAt);
        when(resolution.releaseChallenge(eq("kim01"), any(), any(), any())).thenReturn(true);
        mapped(ContexaAuthentication.of("PASSWORD+OTP").mfa(true).authenticatedAt(signedInAt));
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(false, signedInAt));

        assertThat(service.resolvedByHostReauthentication(request, application, "kim01")).isTrue();

        verify(resolution).markMfaVerified("kim01", signedInAt);
    }

    @Test
    @DisplayName("신원이 밝힌 로그인이 MFA가 아니면 도장이 MFA라 해도 CHALLENGE를 풀지 않는다")
    void theIdentitysOneFactorSignInReleasesNothingWhateverTheStampSays() {
        Instant challengedAt = Instant.now().minusSeconds(120);
        Instant signedInAt = Instant.now().minusSeconds(60);
        when(actions.challengeHeldSince("kim01")).thenReturn(challengedAt);
        when(resolution.releaseChallenge(eq("kim01"), any(), any(), any())).thenReturn(true);
        mapped(ContexaAuthentication.of("PASSWORD").mfa(false).authenticatedAt(signedInAt));
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(true, signedInAt));

        assertThat(service.resolvedByHostReauthentication(request, application, "kim01")).isFalse();

        verify(resolution, never()).releaseChallenge(anyString(), any(), any(), any());
    }

    @Test
    @DisplayName("신원이 로그인 사실을 밝히지 않으면 지금처럼 도장의 MFA와 시각을 읽는다")
    void withoutASignInOfTheIdentityTheStampIsRead() {
        Instant challengedAt = Instant.now().minusSeconds(120);
        Instant stampedAt = Instant.now().minusSeconds(30);
        when(actions.challengeHeldSince("kim01")).thenReturn(challengedAt);
        when(resolution.releaseChallenge(eq("kim01"), any(), any(), any())).thenReturn(true);
        mapped(null);
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(true, stampedAt));

        assertThat(service.resolvedByHostReauthentication(request, application, "kim01")).isTrue();

        verify(resolution).markMfaVerified("kim01", stampedAt);
    }

    @Test
    @DisplayName("패스키 등록 전 사용자 확인도 신원이 밝힌 MFA 로그인을 도장보다 먼저 읽는다")
    void theIdentitysSignInConfirmsTheUserForAPasskeyBeforeTheStamp() {
        when(actions.getCurrentAction(eq("kim01"), any())).thenReturn(ZeroTrustAction.ALLOW);
        Instant signedInAt = Instant.now().minusSeconds(30);
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(false, signedInAt));

        mapped(ContexaAuthentication.of("PASSWORD+OTP").mfa(true).authenticatedAt(signedInAt));
        assertThat(service.situation(request, application).passkeyRegistrable()).isTrue();

        mapped(ContexaAuthentication.of("PASSWORD").mfa(false).authenticatedAt(signedInAt));
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, stamp(true, signedInAt));
        assertThat(service.situation(request, application).passkeyRegistrable()).isFalse();
    }

    @Test
    @DisplayName("패스키 소유자 이름은 매퍼가 이름 지은 ID이고 앱 고유 principal 객체의 글이 아니다")
    void thePasskeyOwnerIsNamedByTheMappedUser() {
        when(actions.getCurrentAction(eq("kim01"), any())).thenReturn(ZeroTrustAction.ALLOW);
        mapped(ContexaAuthentication.of("PASSWORD+OTP").mfa(true).authenticatedAt(Instant.now().minusSeconds(30)));

        service.registrationOptions(request, application);

        ArgumentCaptor<PublicKeyCredentialUserEntity> owner = ArgumentCaptor.forClass(PublicKeyCredentialUserEntity.class);
        verify(entities).save(owner.capture());
        assertThat(owner.getValue().getName()).isEqualTo("brg_kim01");
        assertThat(owner.getValue().getDisplayName()).isEqualTo("kim01").doesNotContain("secret-hash");
    }

    /** The identity the bridge filter makes for the request, with the application's mapper. */
    private void mapped(@Nullable ContexaAuthentication signIn) {
        ContexaSubjectMapper mapper = authentication -> authentication.getPrincipal() instanceof LegacyMember legacy
                ? Optional.of(ContexaSubject.of(legacy.empNo(), legacy.empNo() + "@seum.example")
                        .authentication(signIn)
                        .build())
                : Optional.empty();
        ContexaIdentity identity = new IdentityResolution(IdentityResolution.Settings.defaults(), null, mapper, null,
                IdentityResolution.Accounts.NONE, new IdentityDiagnostics()).resolve(request, application);
        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(ContexaIdentity.subjectId(application)).as("Contexa reads no field of the application's object")
                .isNull();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
    }

    private static AuthenticationStamp stamp(boolean mfa, Instant at) {
        return new AuthenticationStamp("kim01", "kim01", "USER", true, "PASSWORD", "SESSION", null, mfa, at, "s-1",
                List.of(), Map.of());
    }

    /** An application's own principal object, none of the kinds Spring Security names a user by. */
    record LegacyMember(String empNo, String passwordHash) {
    }
}
