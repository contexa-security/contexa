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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-11 of docs/agent/운영모드-정상화-구현계획.md: leaving the static resources outside every security chain is a setting of the
 * whole application's security, which is Contexa's where Contexa is the main security configuration (mode FULL) and the
 * application's own in mode SANDBOX, whoever owns the sign-in.
 */
@DisplayName("정적 자원을 보안 체인 밖에 두는 설정은 FULL에서만 둔다(R-11)")
class StaticResourcesOutsideTheChainByModeTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(IamFullModeInfrastructureConfiguration.class);

    @ParameterizedTest(name = "{0} + {1}: {2}")
    @CsvSource({"SANDBOX, HOST_OWNED, false", "SANDBOX, CONTEXA_OWNED, false", "FULL, HOST_OWNED, true", "FULL, CONTEXA_OWNED, true"})
    @DisplayName("모드가 FULL일 때만 Contexa의 WebSecurityCustomizer가 있다")
    void theStaticResourcesAreLeftOutsideTheChainsInModeFullOnly(String mode, String ownership, boolean expected) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode, ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.containsBean("contexaWebSecurityCustomizer")).isEqualTo(expected);
                });
    }

    @Test
    @DisplayName("운영 방식을 선언하지 않은 앱에는 두지 않는다")
    void anApplicationThatDeclaresNoWayOfRunningKeepsItsStaticResourcesInItsChains() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean("contexaWebSecurityCustomizer");
        });
    }
}
