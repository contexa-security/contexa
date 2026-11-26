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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.ZeroTrustChallengeConfigurer;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.filter.MfaPendingAccessControlFilter;
import io.contexa.contexaidentity.security.zerotrust.PasskeyRegistrationGate;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Q-13 and R-13 of docs/agent/운영모드-정상화-구현계획.md: the passkey registration of a session that has not completed MFA
 * waits for a verification wherever its realm has an MFA flow to verify in. The console's realm has the flow of Contexa's
 * administrators; the application's realm has the application's own MFA flows, and the administrators' flow that joins
 * them is not one of those.
 */
@DisplayName("패스키 등록 관문은 요청의 영역에 MFA 흐름이 있는지로 정한다(Q-13, R-13)")
class PasskeyRegistrationGateByRealmTest {

    private static final Authentication BEFORE_MFA = UsernamePasswordAuthenticationToken.authenticated("admin", null, List.of());

    @Test
    @DisplayName("SANDBOX 기본 설정(관리 흐름뿐): MFA를 마치지 않은 관리자 세션의 패스키 등록은 열리지 않는다")
    void theAdministratorsRegistrationWaitsForTheVerification() {
        PasskeyRegistrationGate gate = gate(flow(ContexaSignInRealm.adminFlowTypeName()));

        assertThat(gate.verdict(console(), BEFORE_MFA)).isEqualTo(PasskeyRegistrationGate.Verdict.VERIFY);
    }

    @Test
    @DisplayName("앱 흐름에 MFA 흐름이 없으면 앱 요청의 관문은 관리 흐름이 붙기 전과 같다(확인할 흐름 없음)")
    void theApplicationsRealmIsAsBeforeTheAdministratorsFlowJoined() {
        PasskeyRegistrationGate gate = gate(flow("form_flow"), flow(ContexaSignInRealm.adminFlowTypeName()));

        assertThat(gate.verdict(new MockHttpServletRequest("POST", "/webauthn/register"), BEFORE_MFA))
                .isEqualTo(PasskeyRegistrationGate.Verdict.OPEN);
        assertThat(gate.verdict(console(), BEFORE_MFA)).as("the console's realm in the same application")
                .isEqualTo(PasskeyRegistrationGate.Verdict.VERIFY);
    }

    /** The gate as Contexa makes it, beside a challenge filter told by the configurer which flows there are. */
    private static PasskeyRegistrationGate gate(AuthenticationFlowConfig... flows) {
        ZeroTrustChallengeFilter challenge = new ZeroTrustChallengeFilter(null, null, null, null, null, null, null, null);
        PlatformConfig.Builder config = PlatformConfig.builder();
        for (AuthenticationFlowConfig flow : flows) {
            config.addFlow(flow);
        }
        new ZeroTrustChallengeConfigurer(challenge).init(null, config.build());
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("contexaZeroTrustChallengeFilter", challenge);
        SecurityZeroTrustProperties properties = mock(SecurityZeroTrustProperties.class);
        when(properties.isEnforcementEnabled()).thenReturn(false);
        return new IdentitySecurityCoreAutoConfiguration().passkeyRegistrationGate(mock(MfaPendingAccessControlFilter.class),
                mock(ZeroTrustActionRepository.class), properties, beans.getBeanProvider(ZeroTrustChallengeFilter.class));
    }

    private static MockHttpServletRequest console() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/webauthn/register");
        ConsoleSession.mark(request);
        return request;
    }

    private static AuthenticationFlowConfig flow(String typeName) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        return flow;
    }
}
