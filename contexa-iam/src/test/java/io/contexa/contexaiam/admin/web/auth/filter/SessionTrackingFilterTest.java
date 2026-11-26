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

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionTrackingFilterTest {

    private static final String RAW = "6F1C2A9B8E7D4C3B2A1908F7E6D5C4B3";

    private final SessionManagementService sessions = mock(SessionManagementService.class);
    private final ActiveSessionRepository tracked = mock(ActiveSessionRepository.class);
    private final MovingClock clock = new MovingClock();
    private final TrackedSessionMarks marks = new TrackedSessionMarks(clock);
    private final SessionTrackingFilter filter = new SessionTrackingFilter(sessions, tracked, marks);

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
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("admin", "x",
                "ROLE_ADMIN")));
        when(tracked.findById(RequestFactRedaction.sessionReference(RAW))).thenReturn(Optional.of(
                ActiveSession.builder().sessionId(RequestFactRedaction.sessionReference(RAW)).expired(true).build()));
        MockHttpServletRequest request = request();
        ConsoleSession.mark(request);
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

    /** R-8: the tracking observes the session's id only; what it keeps to spare the database is Contexa's, not the session's. */
    @Test
    @DisplayName("세션 추적은 앱 세션에 아무 값도 쓰지 않는다(R-8)")
    void theTrackingWritesNothingIntoTheApplicationsSession() throws Exception {
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("alice", "x",
                "ROLE_USER")));
        MockHttpServletRequest request = request();
        MockHttpSession session = (MockHttpSession) request.getSession(false);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), eq("alice"), eq("alice"),
                anyString(), any());
        assertThat(Collections.list(session.getAttributeNames())).isEmpty();
    }

    /** A legacy application's user, known to Contexa from the bridge alone (R-10), has its session tracked as well. */
    @Test
    @DisplayName("Spring 사용자 없이 bridge 신원만 있는 레거시 요청의 세션도 그 사용자로 추적한다")
    void theSessionOfALegacyUserTheBridgeResolvedIsTracked() throws Exception {
        MockHttpServletRequest request = request();
        TestingAuthenticationToken legacyUser = new TestingAuthenticationToken("E1001", null, "ROLE_USER");
        legacyUser.setAuthenticated(true);
        request.setAttribute(BridgeRequestAttributes.IDENTITY, legacyUser);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), eq("E1001"), eq("E1001"),
                anyString(), any());
    }

    /**
     * bridge v2: a user the application signed in with a principal object of its own and named with its
     * {@code ContexaSubjectMapper} is listed under that name, never under the text of the object Contexa does not read.
     */
    @Test
    @DisplayName("앱 고유 principal 객체로 로그인하고 매퍼가 이름 지은 사용자의 세션은 그 ID로 추적한다")
    void theSessionOfAUserTheApplicationsMapperNamedIsTrackedUnderThatName() throws Exception {
        LegacyMember member = new LegacyMember("kim01", "secret-hash");
        Authentication application = UsernamePasswordAuthenticationToken.authenticated(member, null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        SecurityContextHolder.setContext(new SecurityContextImpl(application));
        MockHttpServletRequest request = request();
        ContexaSubjectMapper mapper = authentication -> authentication.getPrincipal() instanceof LegacyMember legacy
                ? Optional.of(ContexaSubject.of(legacy.empNo(), legacy.empNo() + "@seum.example").build())
                : Optional.empty();
        ContexaIdentity identity = new IdentityResolution(IdentityResolution.Settings.defaults(), null, mapper, null,
                IdentityResolution.Accounts.NONE, new IdentityDiagnostics()).resolve(request, application);
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
        assertThat(ContexaIdentity.subjectId(application)).as("Contexa reads no field of the application's object")
                .isNull();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), eq("kim01"), eq("kim01"),
                anyString(), any());
        verify(sessions, never()).trackSession(anyString(), eq(member.toString()), anyString(), anyString(), any());
    }

    /** An application's own principal object, none of the kinds Spring Security names a user by. */
    record LegacyMember(String empNo, String passwordHash) {
    }

    /** The marks on Contexa's side spare the database as the marks in the session did: a read every 10 seconds, a write every 30. */
    @Test
    @DisplayName("만료 확인은 세션마다 10초에, 활동 기록은 30초에 한 번만 저장소에 간다")
    void theDatabaseIsReadEveryTenSecondsAndWrittenEveryThirtyPerSession() throws Exception {
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("alice", "x",
                "ROLE_USER")));
        MockHttpSession session = new MockHttpSession(null, RAW);
        String reference = RequestFactRedaction.sessionReference(RAW);

        send(session);
        clock.advance(Duration.ofSeconds(5));
        send(session);
        verify(tracked, times(1)).findById(reference);
        verify(sessions, times(1)).trackSession(eq(reference), anyString(), anyString(), anyString(), any());

        clock.advance(Duration.ofSeconds(6));
        send(session);
        verify(tracked, times(2)).findById(reference);
        verify(sessions, times(1)).trackSession(eq(reference), anyString(), anyString(), anyString(), any());

        clock.advance(Duration.ofSeconds(20));
        send(session);
        verify(tracked, times(3)).findById(reference);
        verify(sessions, times(2)).trackSession(eq(reference), anyString(), anyString(), anyString(), any());
    }

    /** A sign-in that replaces the session's id during the request: the session is tracked under the id it has now. */
    @Test
    @DisplayName("요청 중에 세션 id가 바뀌면 바뀐 id로 추적하고, 옛 id가 끝나면 그 행을 끝낸다")
    void aSessionWhoseIdTheRequestReplacedIsTrackedUnderItsNewId() throws Exception {
        MockHttpSession anonymous = new MockHttpSession(null, RAW);
        MockHttpSession signedIn = new MockHttpSession(null, "SIGNED-IN-SESSION");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(anonymous);
        FilterChain signIn = (servletRequest, servletResponse) -> {
            ((MockHttpServletRequest) servletRequest).setSession(signedIn);
            SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("alice", "x",
                    "ROLE_USER")));
        };

        filter.doFilter(request, new MockHttpServletResponse(), signIn);

        verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference("SIGNED-IN-SESSION")), eq("alice"),
                eq("alice"), anyString(), any());
        verify(sessions, never()).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), anyString(), anyString(),
                anyString(), any());
        assertThat(marks.trackDue(RequestFactRedaction.sessionReference("SIGNED-IN-SESSION")))
                .as("tracked just now under its new id").isFalse();
        assertThat(Collections.list(signedIn.getAttributeNames())).isEmpty();
    }

    /** A session nobody signed in to has no tracked row: an application's anonymous sessions cost Contexa's database nothing. */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @DisplayName("인증이 없거나 익명 인증인 요청의 세션은 확인·기록하지 않는다")
    void theSessionOfARequestNobodySignedInToIsNeitherReadNorWritten(boolean anonymousAuthentication) throws Exception {
        if (anonymousAuthentication) {
            SecurityContextHolder.setContext(new SecurityContextImpl(new AnonymousAuthenticationToken("key", "anonymousUser",
                    AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))));
        }
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request(), new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
        verify(tracked, never()).findById(anyString());
        verify(sessions, never()).trackSession(anyString(), anyString(), anyString(), anyString(), any());
    }

    /** The application's user whose session the console ended: the application answers its unauthenticated request its own way. */
    @Test
    @DisplayName("강제 종료된 앱 사용자의 화면 GET은 같은 주소로 다시 보낸다")
    void theApplicationsUserForcedOutOnAPageIsSentBackToTheSameAddress() throws Exception {
        forcedOut();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/shop/orders");
        request.setContextPath("/shop");
        request.setQueryString("page=2");
        request.addHeader("Accept", "text/html");
        request.setSession(new MockHttpSession(null, RAW));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(request.getSession(false)).isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/shop/orders?page=2");
    }

    @Test
    @DisplayName("강제 종료된 앱 사용자의 화면 HEAD도 GET처럼 같은 주소로 다시 보낸다")
    void theApplicationsUserForcedOutOnAPageHeadIsSentBackToTheSameAddress() throws Exception {
        forcedOut();
        MockHttpServletRequest request = new MockHttpServletRequest("HEAD", "/orders");
        request.addHeader("Accept", "text/html");
        request.setSession(new MockHttpSession(null, RAW));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(request.getSession(false)).isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/orders");
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "API", "AJAX"})
    @DisplayName("강제 종료된 앱 사용자의 GET 아닌 요청과 API·AJAX 요청은 401을 받는다")
    void theApplicationsUserForcedOutOnAnythingButAPageGetsUnauthorized(String kind) throws Exception {
        forcedOut();
        MockHttpServletRequest request = new MockHttpServletRequest("POST".equals(kind) ? "POST" : "GET", "/orders");
        request.addHeader("Accept", "API".equals(kind) ? "application/json" : "text/html");
        if ("AJAX".equals(kind)) {
            request.addHeader("X-Requested-With", "XMLHttpRequest");
        }
        request.setSession(new MockHttpSession(null, RAW));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(request.getSession(false)).isNull();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getRedirectedUrl()).isNull();
    }

    @Test
    @DisplayName("강제 종료된 콘솔 세션은 관리자 로그인으로 보낸다")
    void aConsoleSessionForcedOutGoesToTheAdministratorsSignIn() throws Exception {
        forcedOut();
        MockHttpServletRequest request = request();
        ConsoleSession.mark(request);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/login");
        assertThat(request.getSession(false)).isNull();
    }

    /** The address a session is listed under is read as everything else of Contexa reads it: past trusted proxies only. */
    @Test
    @DisplayName("기록하는 주소는 신뢰 프록시 기준으로 읽는다")
    void theAddressIsReadPastTrustedProxiesOnly() throws Exception {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getSecurity().setTrustedProxies(List.of("127.0.0.1"));
        SessionFingerprintUtil.bindClientIpResolution(properties);
        try {
            SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("alice", "x",
                    "ROLE_USER")));
            MockHttpServletRequest throughTheProxy = new MockHttpServletRequest("GET", "/orders");
            throughTheProxy.setSession(new MockHttpSession(null, RAW));
            throughTheProxy.setRemoteAddr("127.0.0.1");
            throughTheProxy.addHeader("X-Forwarded-For", "198.51.100.7");
            MockHttpServletRequest spoofed = new MockHttpServletRequest("GET", "/orders");
            spoofed.setSession(new MockHttpSession(null, "SPOOFED-SESSION"));
            spoofed.setRemoteAddr("203.0.113.9");
            spoofed.addHeader("X-Forwarded-For", "198.51.100.8");

            filter.doFilter(throughTheProxy, new MockHttpServletResponse(), new MockFilterChain());
            filter.doFilter(spoofed, new MockHttpServletResponse(), new MockFilterChain());

            verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference(RAW)), eq("alice"), eq("alice"),
                    eq("198.51.100.7"), any());
            verify(sessions).trackSession(eq(RequestFactRedaction.sessionReference("SPOOFED-SESSION")), eq("alice"),
                    eq("alice"), eq("203.0.113.9"), any());
        } finally {
            SessionFingerprintUtil.unbindClientIpResolution(properties);
        }
    }

    private void forcedOut() {
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("alice", "x",
                "ROLE_USER")));
        when(tracked.findById(RequestFactRedaction.sessionReference(RAW))).thenReturn(Optional.of(
                ActiveSession.builder().sessionId(RequestFactRedaction.sessionReference(RAW)).expired(true).build()));
    }

    private void send(MockHttpSession session) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(session);
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
    }

    /** A clock the test moves. */
    static final class MovingClock extends Clock {

        private final AtomicLong millis = new AtomicLong(Instant.parse("2026-11-25T09:00:00Z").toEpochMilli());

        void advance(Duration duration) {
            millis.addAndGet(duration.toMillis());
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public long millis() {
            return millis.get();
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis.get());
        }
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/dashboard");
        request.setSession(new MockHttpSession(null, RAW));
        return request;
    }
}
