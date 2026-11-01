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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * QF-57: a tracked session id is kept until it is certainly dead, so a forced logout keeps reaching every live
 * session while dead ids stop piling up. A token's id lives until the token expires, an HTTP session's id until the
 * container's idle limit has passed since its last request, and an id whose life nothing on the request bounds is kept
 * within a count per user, the least recently seen first out.
 */
class ZeroTrustSessionTrackingDeadlineTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final CountingService service = new CountingService(clock);

    @Test
    void anOpaqueBearerTokensIdIsReleasedOnceTheTokenHasExpired() {
        apply("erin", "opaque-1", opaque("erin", Duration.ofMinutes(10)), request());

        clock.advance(Duration.ofMinutes(10).plusSeconds(30));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("opaque-1")).as("within the clock skew after the expiry").isTrue();

        clock.advance(Duration.ofMinutes(1));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("opaque-1")).isFalse();
    }

    @Test
    void aJwtIdIsReleasedAfterTheTokensExpiryAlsoWhenTheDecisionReplacedTheAuthentication() {
        // A new user's first request is PENDING_ANALYSIS, which replaces the token authentication with a Zero Trust
        // one that no longer carries the token; the id still dies with the token.
        SecurityContextImpl context = new SecurityContextImpl(jwt("frank", "jti-frank", Duration.ofMinutes(5)));
        service.applyZeroTrustToContext(context, "frank", "jti-frank", request());
        assertThat(context.getAuthentication()).isInstanceOf(ZeroTrustAuthenticationToken.class);

        clock.advance(Duration.ofMinutes(7));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("jti-frank")).isFalse();
    }

    @Test
    void anHttpSessionIsTrackedUntilItsIdleLimitHasPassedSinceItsLastRequest() {
        Authentication host = hostAsserted("gina");
        apply("gina", "http-1", host, sessionRequest("http-1", 1800));
        clock.advance(Duration.ofMinutes(5));
        apply("gina", "http-1", host, sessionRequest("http-1", 1800));
        clock.advance(Duration.ofMinutes(11));
        apply("gina", "http-1", host, sessionRequest("http-1", 1800));
        assertThat(service.registrations("http-1"))
                .as("written at the first request and renewed once less than an idle limit was left")
                .isEqualTo(2);

        clock.advance(Duration.ofMinutes(31));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("http-1"))
                .as("the idle limit and the clock skew since the last request have not yet passed").isTrue();

        clock.advance(Duration.ofMinutes(16));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("http-1")).isFalse();
    }

    @Test
    void idsWhoseLifeNothingBoundsAreKeptUpToALimitPerUserTheLeastRecentlySeenFirstOut() {
        Authentication host = hostAsserted("hana");
        for (int i = 0; i < 64; i++) {
            apply("hana", "host-" + i, host, request());
        }
        apply("ivan", "host-ivan", hostAsserted("ivan"), request());
        service.removeExpiredEntries();
        apply("hana", "host-0", host, request());
        apply("hana", "host-64", host, request());

        assertThat(service.tracksSession("host-1")).as("the least recently seen").isFalse();
        assertThat(service.tracksSession("host-0")).as("seen again").isTrue();
        assertThat(IntStream.rangeClosed(2, 64).allMatch(i -> service.tracksSession("host-" + i))).isTrue();
        assertThat(service.tracksSession("host-ivan")).as("another user's").isTrue();

        service.invalidateAllUserSessions("hana", "forced logout");
        assertThat(service.isSessionInvalidated("host-1")).isFalse();
        assertThat(IntStream.of(0, 2, 33, 64).allMatch(i -> service.isSessionInvalidated("host-" + i))).isTrue();
        assertThat(service.isSessionInvalidated("host-ivan")).isFalse();
    }

    @Test
    void anIdReleasedFromTrackingRegistersAgainOnItsNextRequest() {
        apply("kim", "opaque-2", opaque("kim", Duration.ofMinutes(5)), request());
        clock.advance(Duration.ofMinutes(7));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("opaque-2")).isFalse();
        apply("kim", "opaque-2", opaque("kim", Duration.ofMinutes(5)), request());
        assertThat(service.tracksSession("opaque-2")).as("again with a new token").isTrue();

        Authentication host = hostAsserted("lee");
        for (int i = 0; i <= 64; i++) {
            apply("lee", "lee-" + i, host, request());
        }
        assertThat(service.tracksSession("lee-0")).isFalse();
        apply("lee", "lee-0", host, request());
        assertThat(service.tracksSession("lee-0")).as("again without waiting for a sweep").isTrue();
        assertThat(service.tracksSession("lee-1")).as("now the least recently seen").isFalse();
    }

    @Test
    void theLimitPerUserIsTheConfiguredOneAndZeroKeepsEveryId() {
        SecurityZeroTrustProperties limited = new SecurityZeroTrustProperties();
        limited.getSessionTracking().setMaxUntimedSessionsPerUser(2);
        InMemoryZeroTrustSecurityService two = new CountingService(clock, limited);
        SecurityZeroTrustProperties unlimited = new SecurityZeroTrustProperties();
        unlimited.getSessionTracking().setMaxUntimedSessionsPerUser(0);
        InMemoryZeroTrustSecurityService all = new CountingService(clock, unlimited);
        Authentication host = hostAsserted("mia");
        for (int i = 0; i < 70; i++) {
            two.applyZeroTrustToContext(new SecurityContextImpl(host), "mia", "mia-" + i, request());
            all.applyZeroTrustToContext(new SecurityContextImpl(host), "mia", "mia-" + i, request());
        }

        assertThat(IntStream.range(0, 68).noneMatch(i -> two.tracksSession("mia-" + i))).isTrue();
        assertThat(two.tracksSession("mia-68") && two.tracksSession("mia-69")).isTrue();
        assertThat(IntStream.range(0, 70).allMatch(i -> all.tracksSession("mia-" + i))).isTrue();
    }

    @Test
    void forcedLogoutReachesEverySessionStillAlive() {
        Authentication host = hostAsserted("judy");
        apply("judy", "jti-live", jwt("judy", "jti-live", Duration.ofHours(1)), request());
        apply("judy", "opaque-live", opaque("judy", Duration.ofHours(1)), request());
        apply("judy", "http-live", host, sessionRequest("http-live", 1800));
        apply("judy", "host-live", host, request());
        // The HTTP session keeps being used well past the deadline its first request gave it.
        for (int i = 0; i < 5; i++) {
            clock.advance(Duration.ofMinutes(10));
            service.removeExpiredEntries();
            apply("judy", "http-live", host, sessionRequest("http-live", 1800));
        }
        clock.advance(Duration.ofMinutes(5));
        service.removeExpiredEntries();

        service.invalidateAllUserSessions("judy", "forced logout");

        for (String sessionId : List.of("jti-live", "opaque-live", "http-live", "host-live")) {
            assertThat(service.isSessionInvalidated(sessionId)).as(sessionId).isTrue();
        }
    }

    private void apply(String userId, String sessionId, Authentication authentication,
                       MockHttpServletRequest request) {
        service.applyZeroTrustToContext(new SecurityContextImpl(authentication), userId, sessionId, request);
    }

    private static MockHttpServletRequest request() {
        return new MockHttpServletRequest();
    }

    private static MockHttpServletRequest sessionRequest(String sessionId, int maxInactiveSeconds) {
        MockHttpSession session = new MockHttpSession(null, sessionId);
        session.setMaxInactiveInterval(maxInactiveSeconds);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return request;
    }

    private static Authentication hostAsserted(String userId) {
        return UsernamePasswordAuthenticationToken.authenticated(userId, null,
                AuthorityUtils.createAuthorityList("ROLE_AGENT"));
    }

    private Authentication opaque(String userId, Duration lifetime) {
        Instant issuedAt = clock.instant();
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque-value",
                issuedAt, issuedAt.plus(lifetime));
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(userId,
                Map.of("sub", userId), AuthorityUtils.createAuthorityList("SCOPE_reports.read"));
        return new BearerTokenAuthentication(principal, token, principal.getAuthorities());
    }

    private Authentication jwt(String userId, String tokenId, Duration lifetime) {
        Instant issuedAt = clock.instant();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject(userId).jti(tokenId)
                .issuedAt(issuedAt).expiresAt(issuedAt.plus(lifetime)).build();
        return new JwtAuthenticationToken(jwt, AuthorityUtils.createAuthorityList("SCOPE_reports.read"));
    }

    /** Counts the registrations the service writes, by identifier. */
    private static final class CountingService extends InMemoryZeroTrustSecurityService {

        private final Map<String, Integer> writes = new ConcurrentHashMap<>();

        CountingService(AdjustableClock clock) {
            this(clock, new SecurityZeroTrustProperties());
        }

        CountingService(AdjustableClock clock, SecurityZeroTrustProperties properties) {
            super(mock(ThreatScoreUtil.class), properties, new InMemoryZeroTrustActionRepository(),
                    new InMemoryBlockingSignalBroadcaster(), Duration.ofHours(24), clock);
        }

        @Override
        protected void doRegisterSession(String userId, String sessionId, Instant trackUntil) {
            writes.merge(sessionId, 1, Integer::sum);
            super.doRegisterSession(userId, sessionId, trackUntil);
        }

        int registrations(String sessionId) {
            return writes.getOrDefault(sessionId, 0);
        }
    }
}
