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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.security.SessionAccountRefresher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.LocalDateTime;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Q-17, Q-14: what the console's chain adds to its requests. */
class ConsoleSessionFilterTest {

    private static final String KEY = "CONTEXA_ADMIN_SECURITY_CONTEXT";

    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/blacklist");
    private final SessionAccountRefresher refresher = mock(SessionAccountRefresher.class);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("a request of the console's chain is the console's")
    void itMarksTheRequest() throws Exception {
        new ConsoleSessionFilter(KEY, null).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(ConsoleSession.of(request)).isTrue();
    }

    @Test
    @DisplayName("an account that ended signs the console out, and the HTTP session stays the application's")
    void anEndedAccountSignsTheConsoleOut() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("rcboss", "x", "ROLE_ADMIN"));
        request.getSession().setAttribute(KEY, SecurityContextHolder.getContext());
        request.getSession().setAttribute("APPLICATION_STATE", "kept");
        when(refresher.refresh(any(), eq(request), eq(KEY))).thenReturn(SessionAccountRefresher.Outcome.ACCOUNT_ENDED);

        new ConsoleSessionFilter(KEY, refresher).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getSession(false)).isNotNull();
        assertThat(request.getSession(false).getAttribute(KEY)).isNull();
        assertThat(request.getSession(false).getAttribute("APPLICATION_STATE")).isEqualTo("kept");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    private static UnifiedCustomUserDetails administrator(LocalDateTime passwordChangedAt) {
        return new UnifiedCustomUserDetails(UserDto.builder().id(1L).username("rcboss").enabled(true)
                .passwordChangedAt(passwordChangedAt).build(), Set.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    /** Under HOST_OWNED nothing logs a console session out: the version and the account are all that reach it. */
    @Test
    @DisplayName("a new password signs the console out on its next request, and the HTTP session stays the application's")
    void aNewPasswordSignsTheConsoleOut() throws Exception {
        LocalDateTime signedInWith = LocalDateTime.of(2026, 11, 1, 9, 0);
        UnifiedCustomUserDetails signedIn = administrator(signedInWith);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(signedIn, null, signedIn.getAuthorities()));
        request.getSession().setAttribute(KEY, SecurityContextHolder.getContext());
        request.getSession().setAttribute("APPLICATION_STATE", "kept");
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        UserDetailsService accounts = mock(UserDetailsService.class);
        when(accounts.loadUserByUsername("rcboss")).thenReturn(administrator(signedInWith.plusDays(1)));
        store.advanceAuthoritiesVersion();

        new ConsoleSessionFilter(KEY, new SessionAccountRefresher(store, accounts))
                .doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getSession(false).getAttribute(KEY)).isNull();
        assertThat(request.getSession(false).getAttribute("APPLICATION_STATE")).isEqualTo("kept");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("a current account goes on")
    void aCurrentAccountGoesOn() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("rcboss", "x", "ROLE_ADMIN"));
        when(refresher.refresh(any(), eq(request), eq(KEY))).thenReturn(SessionAccountRefresher.Outcome.CURRENT);

        new ConsoleSessionFilter(KEY, refresher).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }
}
