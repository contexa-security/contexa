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
package io.contexa.contexacommon.security;

import io.contexa.contexacommon.domain.UserDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** What a passed MFA opens is the block list and nothing that only reads like it. */
class ConsoleSessionBlockListTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "/contexa/admin", "/contexa/admin/users", "/contexa/admin/blacklistX", "/contexa/admin/blacklist-export",
            "/contexa/admin/api/blacklistX", "/contexa/admin/api/users", "/orders", "/", "",
            "/contexa/admin/blacklist/agents", "/contexa/admin/blacklist/agents/", "/contexa/admin/blacklist/agents/kill-switch",
            "/contexa/admin/blacklist/agents/kill-switch/release", "/contexa/admin/blacklist/agents/release-agent",
            "/contexa/admin/blacklist/../users", "/contexa/admin/blacklist/..;/users", "/contexa/admin/blacklist;a=b/../users",
            "/contexa/admin/blacklist/%2e%2e/users", "/contexa/admin/blacklist%2f..%2fusers", "//contexa/admin/blacklist",
            "/contexa/admin//blacklist", "/contexa/admin/blacklist\\..\\users", "/contexa/admin/blacklist;x=1",
            "/CONTEXA/ADMIN/BLACKLIST"})
    @DisplayName("what only starts like the block list, or leaves it, or is the agents' tab, is not the block list")
    void whatIsNotTheBlockList(String path) {
        assertThat(ConsoleSession.isBlockList(path)).isFalse();
    }

    @Test
    @DisplayName("no path is not the block list")
    void noPath() {
        assertThat(ConsoleSession.isBlockList(null)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/contexa/admin/blacklist", "/contexa/admin/blacklist/", "/contexa/admin/blacklist/7",
            "/contexa/admin/blacklist/7/resolve", "/contexa/admin/blacklist/challenge-release", "/contexa/admin/api/blacklist",
            "/contexa/admin/api/blacklist/7", "/contexa/admin/api/blacklist/7/resolve"})
    @DisplayName("the people of the block list, their pages and their API, are")
    void theBlockList(String path) {
        assertThat(ConsoleSession.isBlockList(path)).isTrue();
    }

    @Test
    @DisplayName("a request of an application's chain is on no release path until the filter says so")
    void onlyTheFilterOpensTheList() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/blacklist");
        request.addHeader("X-Contexa-Console", "true");
        request.setParameter("consoleSession", "true");

        assertThat(ConsoleSession.onReleasePath(request)).isFalse();

        ConsoleSession.openBlockList(request);

        assertThat(ConsoleSession.onReleasePath(request)).isTrue();
        assertThat(ConsoleSession.of(request)).as("it is still no console session").isFalse();
    }

    @Test
    @DisplayName("what the account has decides, not what a decision left the session")
    void anAdministratorIsReadFromTheAccount() {
        UnifiedCustomUserDetails administrator = new UnifiedCustomUserDetails(UserDto.builder().username("boss").build(),
                Set.of(new SimpleGrantedAuthority(ConsoleSession.ADMIN_AUTHORITY)));
        UnifiedCustomUserDetails plain = new UnifiedCustomUserDetails(UserDto.builder().username("plain").build(),
                Set.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(ConsoleSession.administrator(new TestingAuthenticationToken(administrator, "x", "ROLE_BLOCKED"))).isTrue();
        assertThat(ConsoleSession.administrator(new TestingAuthenticationToken(plain, "x", "ROLE_ADMIN")))
                .as("an account without it does not get it from what the session carries").isFalse();
    }

    @Test
    @DisplayName("without an account of Contexa's the authentication's own authorities are read")
    void anotherPrincipalIsReadFromTheAuthentication() {
        assertThat(ConsoleSession.administrator(new TestingAuthenticationToken("boss", "x", "ROLE_ADMIN"))).isTrue();
        assertThat(ConsoleSession.administrator(new TestingAuthenticationToken("boss", "x", "ROLE_BLOCKED"))).isFalse();
        assertThat(ConsoleSession.administrator(new TestingAuthenticationToken("boss", "x", "ROLE_ADMINISTRATOR"))).isFalse();
        assertThat(ConsoleSession.administrator(null)).isFalse();
    }

    @Test
    @DisplayName("no request is on no path")
    void noRequest() {
        assertThat(ConsoleSession.onReleasePath(null)).isFalse();
    }
}
