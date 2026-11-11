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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.zerotrust.ChallengeResolution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An application without webauthn4j has no relying party, and its passkeys cannot be verified. A user whose only way to
 * answer a CHALLENGE is a passkey is then a user who cannot answer, as one with neither a passkey nor an address a code
 * can reach: the page must not offer the passkey, and must say so.
 */
class HostOwnedStepUpWithoutRelyingPartyTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final EmailService email = mock(EmailService.class);
    private final PublicKeyCredentialUserEntityRepository entities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository credentials = mock(UserCredentialRepository.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/step-up");
    private final Authentication alice = new TestingAuthenticationToken("alice", null, "ROLE_USER");

    @BeforeEach
    void setUp() {
        when(actions.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(email.isMailSenderConfigured()).thenReturn(true);
        PublicKeyCredentialUserEntity owner = mock(PublicKeyCredentialUserEntity.class);
        Bytes id = Bytes.random();
        when(owner.getId()).thenReturn(id);
        when(entities.findByUsername("brg_alice")).thenReturn(owner);
        when(credentials.findByUserId(id)).thenReturn(List.of(mock(CredentialRecord.class)));
    }

    private HostOwnedStepUpService service(WebAuthnRelyingPartyOperations relyingParty) {
        return new HostOwnedStepUpService(actions, mock(ChallengeResolution.class), users, "shadow.contexa.local",
                new InMemoryStepUpOptionsStore(), mock(OneTimeTokenService.class), email, relyingParty, entities,
                credentials, null, "/login", 5);
    }

    private void bridged(String address) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(42L);
        when(user.getUsername()).thenReturn("brg_alice");
        when(user.getEmail()).thenReturn(address);
        when(users.findByExternalSubjectIdAndBridgeManagedTrue("alice")).thenReturn(List.of(user));
    }

    @Test
    @DisplayName("with a relying party a registered passkey is offered, as before")
    void withARelyingPartyThePasskeyIsOffered() {
        bridged("brg_alice@shadow.contexa.local");

        assertThat(service(mock(WebAuthnRelyingPartyOperations.class)).situation(request, alice).passkey()).isTrue();
    }

    @Test
    @DisplayName("without one a registered passkey is no way to answer, the same as having none")
    void withoutOneThePasskeyIsNoWayToAnswer() {
        bridged("brg_alice@shadow.contexa.local");
        HostOwnedStepUpService service = service(null);

        HostOwnedStepUpService.Situation situation = service.situation(request, alice);

        assertThat(situation.passkey()).isFalse();
        assertThat(situation.oneTimeCode()).isFalse();
        assertThat(situation.passkeyEnrollable()).isFalse();
        assertThat(situation.purpose()).isEqualTo(HostOwnedStepUpService.Purpose.CHALLENGE);
        assertThat(service.passkeyOptions(request, alice)).isNull();
    }

    @Test
    @DisplayName("without one a user with an address still answers by the code, and the restriction stays in force")
    void withoutOneTheCodeStillAnswers() {
        bridged("alice@corp.example");

        HostOwnedStepUpService.Situation situation = service(null).situation(request, alice);

        assertThat(situation.passkey()).isFalse();
        assertThat(situation.oneTimeCode()).isTrue();
        assertThat(situation.purpose()).isEqualTo(HostOwnedStepUpService.Purpose.CHALLENGE);
    }
}
