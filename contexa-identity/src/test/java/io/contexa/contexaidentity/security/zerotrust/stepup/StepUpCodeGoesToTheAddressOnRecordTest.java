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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.BridgeUserProfile;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Whoever holds a session can change the address the application's profile shows. The step-up's code goes to the
 * address on record, and the copy moves to the new one only once the user proved the address on record with its code,
 * or with a passkey.
 */
class StepUpCodeGoesToTheAddressOnRecordTest {

    private final UserRepository users = mock(UserRepository.class);
    private final BridgeUserProfileRepository profiles = mock(BridgeUserProfileRepository.class);
    private final AtomicReference<Users> copy = new AtomicReference<>();
    private final AtomicReference<BridgeUserProfile> profile = new AtomicReference<>();
    private final DefaultBridgeUserMirrorSyncService sync = new DefaultBridgeUserMirrorSyncService(users, profiles,
            new BridgeProperties(), new ObjectMapper(), null);
    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final ChallengeResolution resolution = new ChallengeResolution(actions, null, null, null, null, null, null);
    private final OneTimeTokenService codes = mock(OneTimeTokenService.class);
    private final EmailService mail = mock(EmailService.class);
    private final WebAuthnRelyingPartyOperations relyingParty = mock(WebAuthnRelyingPartyOperations.class);
    private final PublicKeyCredentialUserEntityRepository entities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository credentials = mock(UserCredentialRepository.class);
    private final HostOwnedStepUpService service = new HostOwnedStepUpService(actions, resolution, users,
            "shadow.contexa.local", new InMemoryStepUpOptionsStore(), codes, mail, relyingParty, entities, credentials,
            null, null, 5);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/step-up/code");
    private final Authentication alice = new TestingAuthenticationToken("alice", null, "ROLE_USER");

    @BeforeEach
    void wire() {
        when(users.findByBridgeSubjectKey(anyString())).thenAnswer(call -> Optional.ofNullable(copy.get()));
        when(users.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(anyString(), anyString()))
                .thenAnswer(call -> Optional.ofNullable(copy.get()));
        when(users.findById(anyLong())).thenAnswer(call -> Optional.ofNullable(copy.get()));
        when(users.findFirstByEmailIgnoreCase(anyString())).thenReturn(Optional.empty());
        when(users.save(any(Users.class))).thenAnswer(call -> {
            Users user = call.getArgument(0);
            if (user.getId() == null) {
                user.setId(100L);
            }
            copy.set(user);
            return user;
        });
        when(users.findByExternalSubjectIdAndBridgeManagedTrue("alice")).thenAnswer(call -> List.of(copy.get()));
        when(profiles.findById(anyLong())).thenAnswer(call -> Optional.ofNullable(profile.get()));
        when(profiles.save(any(BridgeUserProfile.class))).thenAnswer(call -> {
            profile.set(call.getArgument(0));
            return call.getArgument(0);
        });
        when(mail.isMailSenderConfigured()).thenReturn(true);
        when(codes.generate(any())).thenReturn(new DefaultOneTimeToken("123456", "step-up:100",
                Instant.now().plusSeconds(300)));
        when(codes.consume(any())).thenAnswer(call -> "123456".equals(
                call.getArgument(0, OneTimeTokenAuthenticationToken.class).getTokenValue())
                ? new DefaultOneTimeToken("123456", "step-up:100", Instant.now().plusSeconds(300)) : null);
        service.setUserMirror(sync);
    }

    private void shows(String email) {
        sync.sync(new AuthenticationStamp("alice", "Alice", "USER", true, "FORM", "SECURITY_CONTEXT", null, null, null,
                        "s-1", List.of("ROLE_USER"), Map.of("email", email)), null,
                new RequestContextSnapshot("/profile", "POST", "198.51.100.9", "ua", "s-1", "r-1", "/profile", null,
                        false, Instant.now()));
    }

    private String mailedTo() {
        ArgumentCaptor<String> to = ArgumentCaptor.forClass(String.class);
        verify(mail).sendHtmlMessage(to.capture(), anyString(), anyString());
        return to.getValue();
    }

    @Test
    @DisplayName("the code goes to the address of the owner")
    void theCodeGoesToTheOwner() {
        shows("alice@corp.example");
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());

        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);

        assertThat(mailedTo()).isEqualTo("alice@corp.example");
    }

    @Test
    @DisplayName("an address changed on the application's profile does not get the code")
    void aChangedProfileAddressDoesNotGetTheCode() {
        shows("alice@corp.example");
        shows("thief@evil.example");
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());

        assertThat(service.sendCode(request, alice)).isEqualTo(HostOwnedStepUpService.CodeSending.SENT);

        assertThat(mailedTo()).isEqualTo("alice@corp.example");
        assertThat(copy.get().getEmail()).isEqualTo("alice@corp.example");
    }

    @Test
    @DisplayName("the code of the address on record moves the copy to the address the application shows")
    void theCodeOfTheAddressOnRecordMovesTheAddress() {
        shows("alice@corp.example");
        shows("alice@home.example");
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        service.sendCode(request, alice);
        assertThat(mailedTo()).isEqualTo("alice@corp.example");

        assertThat(service.verifyCode(request, alice, "123456")).isTrue();

        assertThat(copy.get().getEmail()).isEqualTo("alice@home.example");
        assertThat(profile.get().getPendingEmail()).isNull();
    }

    @Test
    @DisplayName("a wrong code moves nothing")
    void aWrongCodeMovesNothing() {
        shows("alice@corp.example");
        shows("thief@evil.example");
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        service.sendCode(request, alice);

        assertThat(service.verifyCode(request, alice, "000000")).isFalse();

        assertThat(copy.get().getEmail()).isEqualTo("alice@corp.example");
        assertThat(profile.get().getPendingEmail()).isEqualTo("thief@evil.example");
    }

    @Test
    @DisplayName("the user's passkey moves the copy to the address the application shows")
    @SuppressWarnings("unchecked")
    void thePasskeyMovesTheAddress() {
        shows("alice@corp.example");
        shows("alice@home.example");
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        String owner = copy.get().getUsername();
        PublicKeyCredentialUserEntity entity = mock(PublicKeyCredentialUserEntity.class);
        when(entity.getId()).thenReturn(Bytes.random());
        when(entity.getName()).thenReturn(owner);
        when(entities.findByUsername(owner)).thenReturn(entity);
        when(credentials.findByUserId(any())).thenReturn(List.of(mock(CredentialRecord.class)));
        when(relyingParty.createCredentialRequestOptions(any())).thenReturn(
                mock(PublicKeyCredentialRequestOptions.class));
        when(relyingParty.authenticate(any())).thenReturn(entity);
        assertThat(copy.get().getEmail()).isEqualTo("alice@corp.example");

        assertThat(service.passkeyOptions(request, alice)).isNotNull();
        assertThat(service.verifyPasskey(request, alice, mock(PublicKeyCredential.class))).isTrue();

        assertThat(copy.get().getEmail()).isEqualTo("alice@home.example");
        assertThat(profile.get().getPendingEmail()).isNull();
    }

    @Test
    @DisplayName("a step-up without the copy's sync service passes as before and moves nothing")
    void withoutTheSyncService() {
        service.setUserMirror(null);
        shows("alice@corp.example");
        shows("alice@home.example");
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        service.sendCode(request, alice);

        assertThat(service.verifyCode(request, alice, "123456")).isTrue();

        assertThat(copy.get().getEmail()).isEqualTo("alice@corp.example");
    }
}
