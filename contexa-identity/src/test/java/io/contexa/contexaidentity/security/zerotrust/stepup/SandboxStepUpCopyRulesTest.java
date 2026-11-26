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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Bridge v2 B5-1: the step-up finds the copy by the decision key and mails no code to an address others share. */
@DisplayName("추가 인증의 사본 조회와 메일 수단 규칙")
class SandboxStepUpCopyRulesTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final ChallengeResolution resolution = mock(ChallengeResolution.class);
    private final UserRepository users = mock(UserRepository.class);
    private final OneTimeTokenService oneTimeTokens = mock(OneTimeTokenService.class);
    private final EmailService email = mock(EmailService.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/step-up");
    private SandboxStepUpService service;

    @BeforeEach
    void setUp() {
        service = new SandboxStepUpService(actions, resolution, users, "shadow.contexa.local",
                new InMemoryStepUpOptionsStore(), oneTimeTokens, email, null, null, null, null,
                "/login?prompt=login", 5);
        when(email.isMailSenderConfigured()).thenReturn(true);
        when(actions.getCurrentAction(anyString(), any())).thenReturn(ZeroTrustAction.CHALLENGE);
    }

    private Users copy(String decisionKey, String address) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(42L);
        when(user.getUsername()).thenReturn("brg_" + decisionKey);
        when(user.getEmail()).thenReturn(address);
        when(user.isBridgeManaged()).thenReturn(true);
        when(users.findByExternalSubjectIdAndBridgeManagedTrue(decisionKey)).thenReturn(List.of(user));
        return user;
    }

    @Test
    @DisplayName("다른 사용자와 같은 메일인 사본에는 추가 인증 코드를 보내지 않는다")
    void noCodeToAnAddressOthersShare() {
        copy("alice", "team@corp.example");
        when(users.countByEmailIgnoreCase("team@corp.example")).thenReturn(2L);

        SandboxStepUpService.Situation situation = service.situation(request,
                new TestingAuthenticationToken("alice", null, "ROLE_USER"));

        assertThat(situation.user()).isNotNull();
        assertThat(situation.oneTimeCode()).isFalse();
        assertThat(service.sendCode(request, new TestingAuthenticationToken("alice", null, "ROLE_USER")))
                .isEqualTo(SandboxStepUpService.CodeSending.UNAVAILABLE);
        verifyNoInteractions(oneTimeTokens);
    }

    @Test
    @DisplayName("메일이 하나뿐인 사본에는 추가 인증 코드를 보낼 수 있다")
    void aCodeToAnAddressOfItsOwn() {
        copy("alice", "alice@corp.example");
        when(users.countByEmailIgnoreCase("alice@corp.example")).thenReturn(1L);

        SandboxStepUpService.Situation situation = service.situation(request,
                new TestingAuthenticationToken("alice", null, "ROLE_USER"));

        assertThat(situation.oneTimeCode()).isTrue();
    }

    @Test
    @DisplayName("메일이 없는 사본에는 추가 인증 코드를 보내지 않는다")
    void noCodeToACopyWithoutAnAddress() {
        copy("alice", null);

        SandboxStepUpService.Situation situation = service.situation(request,
                new TestingAuthenticationToken("alice", null, "ROLE_USER"));

        assertThat(situation.oneTimeCode()).isFalse();
    }

    @Test
    @DisplayName("대문자로 들어온 아이디도 판정 키(접은 아이디)로 저장된 사본을 찾는다")
    void aCopyIsFoundByTheDecisionKeyOfTheId() {
        Users stored = copy("alice", "alice@corp.example");

        SandboxStepUpService.Situation situation = service.situation(request,
                new TestingAuthenticationToken("Alice", null, "ROLE_USER"));

        assertThat(situation.user()).isSameAs(stored);
    }
}
