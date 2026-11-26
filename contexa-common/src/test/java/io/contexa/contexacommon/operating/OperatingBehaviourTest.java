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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-12 of the operating-mode plan (docs/agent/운영모드-정상화-구현계획.md): who signs the application's users in, and so
 * who builds the main chain, writes their security context and enforces on their requests, follows the mode; how Contexa
 * gives way to the application's components and whether its administrators sign in apart follows the ownership.
 */
@DisplayName("운영 동작은 모드와 소유권을 각자 맡은 만큼만 따른다(R-12)")
class OperatingBehaviourTest {

    @ParameterizedTest(name = "{0} + {1}")
    @CsvSource({
            "SANDBOX, HOST_OWNED,    false, false, true,  true,  true",
            "SANDBOX, CONTEXA_OWNED, false, false, true,  true,  false",
            "FULL,    HOST_OWNED,    true,  true,  false, true,  true",
            "FULL,    CONTEXA_OWNED, true,  true,  false, false, false"})
    @DisplayName("네 조합의 동작표")
    void everyCombinationAnswersWhatItDecides(SecurityMode mode, SecurityOwnershipMode ownership, boolean mainChain,
                                              boolean writesContext, boolean servletFilters, boolean adminRealmApart,
                                              boolean hostComponentsWin) {
        OperatingBehaviour behaviour = OperatingBehaviour.of(mode, ownership);

        assertThat(behaviour.buildsMainChain()).isEqualTo(mainChain);
        assertThat(behaviour.signsInTheApplicationsUsers()).isEqualTo(mainChain);
        assertThat(behaviour.writesSecurityContext()).isEqualTo(writesContext);
        assertThat(behaviour.enforcesFromServletFilters()).isEqualTo(servletFilters);
        assertThat(behaviour.adminRealmOnItsOwnChain()).isEqualTo(adminRealmApart);
        assertThat(behaviour.hostComponentsWin()).isEqualTo(hostComponentsWin);
    }

    @Test
    @DisplayName("환경이 없는 bridge 설정은 소유권에 맞는 모드로 답한다")
    void theBridgePropertiesWithoutAnEnvironmentTakeTheModeThatGoesWithTheirOwnership() {
        BridgeProperties properties = new BridgeProperties();

        assertThat(properties.operatingBehaviour()).isEqualTo(OperatingBehaviour.of(SecurityMode.SANDBOX, SecurityOwnershipMode.HOST_OWNED));

        properties.setOwnership(SecurityOwnershipMode.CONTEXA_OWNED);

        assertThat(properties.operatingBehaviour()).isEqualTo(OperatingBehaviour.of(SecurityMode.FULL, SecurityOwnershipMode.CONTEXA_OWNED));
    }

    @Test
    @DisplayName("bridge 설정은 @EnableAISecurity가 알린 모드와 자기 소유권으로 답한다")
    void theBridgePropertiesAnswerForThePublishedModeAndTheirOwnership() {
        BridgeProperties properties = new BridgeProperties();
        properties.setEnvironment(new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, "FULL"));
        properties.setOwnership(SecurityOwnershipMode.HOST_OWNED);

        OperatingBehaviour behaviour = properties.operatingBehaviour();

        assertThat(behaviour.mode()).isEqualTo(SecurityMode.FULL);
        assertThat(behaviour.ownership()).isEqualTo(SecurityOwnershipMode.HOST_OWNED);
        assertThat(behaviour.buildsMainChain()).isTrue();
        assertThat(behaviour.hostComponentsWin()).isTrue();
    }
}
