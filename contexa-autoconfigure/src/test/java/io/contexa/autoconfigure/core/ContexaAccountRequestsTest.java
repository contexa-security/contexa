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
package io.contexa.autoconfigure.core;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.ConsoleSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Whose account a sign-in is (docs/agent/운영모드-정상화-구현계획.md): Contexa's console signs Contexa's accounts in everywhere,
 * and the application's users are Contexa's accounts only where Contexa's main chain signs them in with Contexa's own store.
 */
@DisplayName("Contexa 계정 로그인 판단: 콘솔 요청이거나 FULL+CONTEXA_OWNED일 때만 Contexa 계정이다")
class ContexaAccountRequestsTest {

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @ParameterizedTest(name = "{0} {1} -> {2}")
    @CsvSource({"SANDBOX,HOST_OWNED,false", "SANDBOX,CONTEXA_OWNED,false", "FULL,HOST_OWNED,false", "FULL,CONTEXA_OWNED,true"})
    @DisplayName("콘솔이 아닌 요청의 로그인은 FULL+CONTEXA_OWNED에서만 Contexa 계정이다")
    void outsideTheConsoleOnlyFullWithContexaOwnedSignsContexasAccountsIn(String mode, String ownership, boolean contexas) {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest("POST", "/login")));

        assertThat(ContexaAccountRequests.of(environment(mode, ownership)).getAsBoolean()).isEqualTo(contexas);
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({"SANDBOX,HOST_OWNED", "SANDBOX,CONTEXA_OWNED", "FULL,HOST_OWNED", "FULL,CONTEXA_OWNED"})
    @DisplayName("콘솔 요청의 로그인은 어느 조합에서나 Contexa 계정이다")
    void inTheConsoleEveryCombinationSignsContexasAccountsIn(String mode, String ownership) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login");
        ConsoleSession.mark(request);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        assertThat(ContexaAccountRequests.of(environment(mode, ownership)).getAsBoolean()).isTrue();
    }

    @ParameterizedTest(name = "{0} {1} -> {2}")
    @CsvSource({"SANDBOX,HOST_OWNED,false", "FULL,CONTEXA_OWNED,true"})
    @DisplayName("요청 밖의 로그인 이벤트는 앱 사용자 규칙만 따른다")
    void withoutARequestOnlyTheRuleOfTheApplicationsUsersCounts(String mode, String ownership, boolean contexas) {
        assertThat(ContexaAccountRequests.of(environment(mode, ownership)).getAsBoolean()).isEqualTo(contexas);
    }

    private static MockEnvironment environment(String mode, String ownership) {
        return new MockEnvironment()
                .withProperty(ContexaOperatingProfile.PROP_MODE, mode)
                .withProperty(ContexaOperatingProfile.PROP_OWNERSHIP, ownership);
    }
}
