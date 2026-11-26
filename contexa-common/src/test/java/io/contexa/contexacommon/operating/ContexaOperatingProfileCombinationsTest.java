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

import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-1 of the operating-mode plan (docs/agent/운영모드-정상화-구현계획.md): the mode and the ownership of the sign-in are two
 * settings. Every pair of them is a way of running Contexa, and the ownership follows the mode only where it is not set.
 */
@DisplayName("운영 모드와 소유권은 독립된 두 설정이다(R-1)")
class ContexaOperatingProfileCombinationsTest {

    @ParameterizedTest(name = "{0} + {1}")
    @CsvSource({"SANDBOX, HOST_OWNED", "SANDBOX, CONTEXA_OWNED", "FULL, HOST_OWNED", "FULL, CONTEXA_OWNED"})
    @DisplayName("네 조합 모두 프로필이 되고 적은 모드와 소유권이 그대로 남는다")
    void everyPairIsAWayOfRunningContexa(SecurityMode mode, SecurityOwnershipMode ownership) {
        MockEnvironment environment = new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_OWNERSHIP, ownership.name());

        ContexaOperatingProfile profile = ContexaOperatingProfile.of(mode, environment);

        assertThat(profile.mode()).isEqualTo(mode);
        assertThat(profile.ownership()).isEqualTo(ownership);
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({"SANDBOX, HOST_OWNED", "FULL, CONTEXA_OWNED"})
    @DisplayName("소유권을 적지 않으면 모드의 기본 소유권을 쓴다")
    void anUnsetOwnershipFollowsTheMode(SecurityMode mode, SecurityOwnershipMode ownership) {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(mode, new MockEnvironment());

        assertThat(profile.mode()).isEqualTo(mode);
        assertThat(profile.ownership()).isEqualTo(ownership);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({"SANDBOX, CONTEXA_OWNED", "FULL, HOST_OWNED"})
    @DisplayName("모드를 바꿔 적어도 적은 소유권이 그대로 남는다(운영자 설정이 코드의 모드보다 앞선다)")
    void anOperatorsModeKeepsTheOwnershipItWasGiven(SecurityMode mode, SecurityOwnershipMode ownership) {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(ContexaOperatingProfile.PROP_MODE, mode.name())
                .withProperty(ContexaOperatingProfile.PROP_OWNERSHIP, ownership.name());

        ContexaOperatingProfile profile = ContexaOperatingProfile.resolve(environment);

        assertThat(profile.mode()).isEqualTo(mode);
        assertThat(profile.ownership()).isEqualTo(ownership);
    }
}
