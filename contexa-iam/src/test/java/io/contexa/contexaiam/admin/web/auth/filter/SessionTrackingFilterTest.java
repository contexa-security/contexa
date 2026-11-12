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
package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionTrackingFilterTest {

    private static final String RAW = "6F1C2A9B8E7D4C3B2A1908F7E6D5C4B3";

    private final SessionManagementService sessions = mock(SessionManagementService.class);
    private final ActiveSessionRepository tracked = mock(ActiveSessionRepository.class);
    private final SessionTrackingFilter filter = new SessionTrackingFilter(sessions, tracked);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    /** PR-65: a session forced out kept reaching these paths of the application. */
    @ParameterizedTest
    @ValueSource(strings = {"/favicon-report", "/faviconreport", "/actuator/env", "/demo/export", "/webjars-report",
            "/contexa/js/..;/..;/owners/1", "/contexa/admin/api/guided-audit"})
    void aPathOfTheApplicationMeetsTheForcedInvalidation(String path) {
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", path))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/favicon.ico", "/contexa/js/toast.js", "/contexa/css/main.css", "/contexa/img/logo.png",
            "/webjars/app.js", "/contexa/admin/test/guided", "/contexa/admin/api/guided/run"})
    void aFileOrAPathOfContexasIsNotTracked(String path) {
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", path))).isTrue();
    }

    @Test
    void theContextPathIsNotPartOfThePath() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/favicon.ico");
        request.setContextPath("/app");

        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    /** The tracked sessions are kept by their references: the session the console forced out is found by its own. */
    @Test
    void aSessionTheConsoleForcedOutIsFoundByItsReferenceAndForcedOut() throws Exception {
        when(tracked.findById(RequestFactRedaction.sessionReference(RAW))).thenReturn(Optional.of(
                ActiveSession.builder().sessionId(RequestFactRedaction.sessionReference(RAW)).expired(true).build()));
        MockHttpServletRequest request = request();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/login");
        assertThat(request.getSession(false)).isNull();
        verify(tracked, never()).findById(RAW);
    }

    /** A session is tracked by its reference, never by the value its cookie carries. */
    @Test
    void aSessionIsTrackedByItsReferenceNeverByTheValueItsCookieCarries() throws Exception {
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("admin", "x",
                "ROLE_ADMIN")));
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request(), new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
        verify(tracked).findById(RequestFactRedaction.sessionReference(RAW));
        verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), eq("admin"), eq("admin"),
                anyString(), any());
        verify(sessions, never()).trackSession(eq(RAW), anyString(), anyString(), anyString(), any());
    }

    /** PR-196: the tracked sessions are read and written as Contexa's own work; the application's part of the request is not. */
    @Test
    void theTrackedSessionsAreReadAndWrittenAsContexasOwnWorkAndTheApplicationRunsOutsideIt() throws Exception {
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("admin", "x",
                "ROLE_ADMIN")));
        List<String> seen = new ArrayList<>();
        when(tracked.findById(RequestFactRedaction.sessionReference(RAW))).thenAnswer(call -> {
            seen.add("read " + RequestPathScope.inContexaWork());
            return Optional.empty();
        });
        doAnswer(call -> {
            seen.add("tracked " + RequestPathScope.inContexaWork());
            return null;
        }).when(sessions).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), eq("admin"), eq("admin"),
                anyString(), any());
        FilterChain chain = (request, response) -> seen.add("application " + RequestPathScope.inContexaWork());

        filter.doFilter(request(), new MockHttpServletResponse(), chain);

        assertThat(seen).containsExactly("read true", "application false", "tracked true");
        assertThat(RequestPathScope.inContexaWork()).isFalse();
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/dashboard");
        request.setSession(new MockHttpSession(null, RAW));
        return request;
    }
}
