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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-11 ① of docs/agent/운영모드-정상화-구현계획.md: Contexa's database stays out of the application's health unless it is the
 * application's own database too. That is what the profile decides for the application's data, whoever owns the sign-in.
 */
@DisplayName("Contexa DB를 앱 건강에서 빼는 일은 Contexa DB가 앱 데이터를 맡는지로 정한다(R-11 ①)")
class HostHealthByApplicationDataTest {

    private static final String BEAN = "contexaHostHealthWithoutContexaDatabase";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(HostHealthConfiguration.class);

    @ParameterizedTest(name = "{0} + {1}, Contexa's database holds the application's data: {2}")
    @CsvSource({
            "SANDBOX, HOST_OWNED, false, true",
            "SANDBOX, CONTEXA_OWNED, false, true",
            "FULL, HOST_OWNED, false, true",
            "FULL, CONTEXA_OWNED, false, true",
            "SANDBOX, HOST_OWNED, true, false",
            "FULL, HOST_OWNED, true, false",
            "FULL, CONTEXA_OWNED, true, false"})
    @DisplayName("Contexa DB가 앱 데이터를 맡지 않으면 앱 건강에서 뺀다")
    void contexasDatabaseLeavesTheApplicationsHealthUnlessItHoldsTheApplicationsData(String mode, String ownership,
                                                                                     boolean contexaHoldsTheData,
                                                                                     boolean left) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode,
                        ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership,
                        ContexaOperatingProfile.PROP_APPLICATION_DATA + "=" + contexaHoldsTheData)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.containsBean(BEAN)).isEqualTo(left);
                });
    }

    @Test
    @DisplayName("앱 데이터 값이 아직 없으면(운영 방식 미선언) 앱 건강에서 뺀다")
    void withoutTheValueOfTheApplicationsDataContexasDatabaseLeavesTheApplicationsHealth() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean(BEAN);
        });
    }
}
