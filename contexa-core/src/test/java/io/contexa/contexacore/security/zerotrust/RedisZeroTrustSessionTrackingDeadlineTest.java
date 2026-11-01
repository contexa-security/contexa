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

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.DataType;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
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

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * QF-57 on Redis: the same tracking as the in-memory service. An id registered with a deadline is neither kept nor
 * reached by a forced logout once it is dead, and a user with only such ids leaves no key behind; ids without a
 * deadline are kept up to the per-user limit; every live id, and every id of the user's session list, stays reachable.
 */
@EnabledIf("io.contexa.contexacore.security.zerotrust.RedisZeroTrustSessionTrackingDeadlineTest#isLocalRedisAvailable")
class RedisZeroTrustSessionTrackingDeadlineTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;

    private final RedisZeroTrustSecurityService service = new RedisZeroTrustSecurityService(redis,
            mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(), new InMemoryZeroTrustActionRepository());
    private final List<String> users = new ArrayList<>();
    private final List<String> sessionIds = new ArrayList<>();

    static boolean isLocalRedisAvailable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(REDIS_HOST, REDIS_PORT), 500);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(REDIS_HOST, REDIS_PORT));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void removeWrittenKeys() {
        for (String user : users) {
            Set<String> keys = keysOf(user);
            if (!keys.isEmpty()) {
                redis.delete(keys);
            }
        }
        for (String sessionId : sessionIds) {
            redis.delete(ZeroTrustRedisKeys.invalidSession(sessionId));
        }
    }

    @Test
    void anIdPastItsDeadlineIsNeitherKeptNorReachedAndTheUsersKeysExpireWithTheLastDeadline() throws Exception {
        String user = user();
        String dead = sessionId("dead");
        String shortLived = sessionId("short");
        String live = sessionId("live");
        String later = sessionId("later");
        Instant now = Instant.now();
        service.doRegisterSession(user, dead, now.minusSeconds(1));
        service.doRegisterSession(user, shortLived, now.plusMillis(300));
        service.doRegisterSession(user, live, now.plus(Duration.ofHours(1)));
        Thread.sleep(600);
        service.doRegisterSession(user, later, now.plus(Duration.ofHours(1)));

        assertThat(storedIds(user)).contains(live, later).doesNotContain(dead, shortLived);
        assertThat(keysOf(user)).isNotEmpty().allSatisfy(key -> assertThat(redis.getExpire(key, TimeUnit.MILLISECONDS))
                .as(key).isPositive().isLessThanOrEqualTo(Duration.ofHours(1).toMillis()));

        service.invalidateAllUserSessions(user, "forced logout");
        assertThat(service.isSessionInvalidated(live)).isTrue();
        assertThat(service.isSessionInvalidated(later)).isTrue();
        assertThat(service.isSessionInvalidated(dead)).isFalse();
        assertThat(service.isSessionInvalidated(shortLived)).isFalse();
    }

    @Test
    void aLaterRegistrationExtendsTheDeadlineAndAnEarlierOneNeverShortensIt() throws Exception {
        String user = user();
        String kept = sessionId("kept");
        String renewed = sessionId("renewed");
        String lapsed = sessionId("lapsed");
        Instant now = Instant.now();
        service.doRegisterSession(user, kept, now.plus(Duration.ofHours(1)));
        service.doRegisterSession(user, kept, now.minusSeconds(1));
        service.doRegisterSession(user, renewed, now.plusMillis(300));
        service.doRegisterSession(user, lapsed, now.plusMillis(300));
        Thread.sleep(600);
        service.doRegisterSession(user, renewed, Instant.now().plus(Duration.ofHours(1)));

        service.invalidateAllUserSessions(user, "forced logout");

        assertThat(service.isSessionInvalidated(kept)).isTrue();
        assertThat(service.isSessionInvalidated(renewed)).isTrue();
        assertThat(service.isSessionInvalidated(lapsed)).isFalse();
    }

    @Test
    void idsWithoutADeadlineAreKeptUpToTheLimitPerUserAndAReleasedOneRegistersAgain() throws Exception {
        String user = user();
        String other = user();
        List<String> ids = IntStream.rangeClosed(0, 64).mapToObj(i -> sessionId("host-" + i)).toList();
        for (int i = 0; i < 64; i++) {
            service.doRegisterSession(user, ids.get(i));
            Thread.sleep(3);
        }
        String othersId = sessionId("other");
        service.doRegisterSession(other, othersId);
        Thread.sleep(3);
        service.doRegisterSession(user, ids.get(0));
        Thread.sleep(3);
        service.doRegisterSession(user, ids.get(64));

        assertThat(storedIds(user)).doesNotContain(ids.get(1)).contains(ids.get(0), ids.get(2), ids.get(64))
                .hasSize(64);
        assertThat(storedIds(other)).containsExactly(othersId);

        Thread.sleep(3);
        service.doRegisterSession(user, ids.get(1));
        assertThat(storedIds(user)).contains(ids.get(1)).doesNotContain(ids.get(2)).hasSize(64);

        service.invalidateAllUserSessions(user, "forced logout");
        assertThat(service.isSessionInvalidated(ids.get(2))).isFalse();
        assertThat(IntStream.of(0, 1, 3, 40, 64).allMatch(i -> service.isSessionInvalidated(ids.get(i)))).isTrue();
        assertThat(service.isSessionInvalidated(othersId)).isFalse();
    }

    @Test
    void theLimitPerUserIsTheConfiguredOneAndZeroKeepsEveryId() throws Exception {
        SecurityZeroTrustProperties limited = new SecurityZeroTrustProperties();
        limited.getSessionTracking().setMaxUntimedSessionsPerUser(2);
        RedisZeroTrustSecurityService two = new RedisZeroTrustSecurityService(redis, mock(ThreatScoreUtil.class),
                limited, new InMemoryZeroTrustActionRepository());
        SecurityZeroTrustProperties unlimited = new SecurityZeroTrustProperties();
        unlimited.getSessionTracking().setMaxUntimedSessionsPerUser(0);
        RedisZeroTrustSecurityService all = new RedisZeroTrustSecurityService(redis, mock(ThreatScoreUtil.class),
                unlimited, new InMemoryZeroTrustActionRepository());
        String limitedUser = user();
        String unlimitedUser = user();
        List<String> ids = IntStream.range(0, 70).mapToObj(i -> sessionId("n-" + i)).toList();
        for (String id : ids) {
            two.doRegisterSession(limitedUser, id);
            all.doRegisterSession(unlimitedUser, id);
            Thread.sleep(3);
        }

        assertThat(storedIds(limitedUser)).containsExactlyInAnyOrder(ids.get(68), ids.get(69));
        assertThat(storedIds(unlimitedUser)).hasSize(70);
    }

    @Test
    void forcedLogoutReachesEveryLiveIdAndEveryIdOfTheUsersSessionList() {
        String user = user();
        String opaque = sessionId("opaque");
        String token = sessionId("jti");
        String http = sessionId("http");
        String host = sessionId("host");
        String listed = sessionId("listed");
        apply(user, opaque, opaque(user), new MockHttpServletRequest());
        apply(user, token, jwt(user, token), new MockHttpServletRequest());
        apply(user, http, hostAsserted(user), sessionRequest(http));
        apply(user, host, hostAsserted(user), new MockHttpServletRequest());
        redis.opsForSet().add(ZeroTrustRedisKeys.userSessions(user), listed);

        service.invalidateAllUserSessions(user, "forced logout");

        for (String sessionId : List.of(opaque, token, http, host, listed)) {
            assertThat(service.isSessionInvalidated(sessionId)).as(sessionId).isTrue();
        }
        // Z-16 (2-d): the tracking keys go; the context store's session list stays, its recent requests still counted.
        assertThat(keysOf(user)).containsExactly(ZeroTrustRedisKeys.userSessions(user));
    }

    @Test
    void trackingLeavesTheUsersSessionListToTheContextStore() {
        // The user's session list (ZeroTrustRedisKeys.userSessions) is also the context store's list of the user's
        // sessions, whose recent requests the analysis counts; tracking keeps its own keys and does not change it.
        String user = user();
        apply(user, sessionId("opaque"), opaque(user), new MockHttpServletRequest());
        apply(user, sessionId("host"), hostAsserted(user), new MockHttpServletRequest());

        assertThat(redis.opsForSet().members(ZeroTrustRedisKeys.userSessions(user))).isEmpty();
    }

    @Test
    void aLogoutReleasesOnlyItsOwnSession() {
        String user = user();
        String a = sessionId("a");
        String b = sessionId("b");
        service.doRegisterSession(user, a);
        service.doRegisterSession(user, b, Instant.now().plus(Duration.ofHours(1)));

        service.cleanupOnLogout(user, b);
        service.invalidateAllUserSessions(user, "forced logout");

        assertThat(service.isSessionInvalidated(a)).isTrue();
        assertThat(service.isSessionInvalidated(b)).isFalse();
    }

    private void apply(String userId, String sessionId, Authentication authentication,
                       MockHttpServletRequest request) {
        service.applyZeroTrustToContext(new SecurityContextImpl(authentication), userId, sessionId, request);
    }

    private String user() {
        String user = "qf57-user-" + UUID.randomUUID();
        users.add(user);
        return user;
    }

    private String sessionId(String kind) {
        String sessionId = "qf57-sid-" + UUID.randomUUID() + "-" + kind;
        sessionIds.add(sessionId);
        return sessionId;
    }

    private static Set<String> keysOf(String user) {
        Set<String> keys = redis.keys("*" + user + "*");
        return keys != null ? keys : Set.of();
    }

    /** Every id any key of the user holds. */
    private static Set<String> storedIds(String user) {
        Set<String> ids = new HashSet<>();
        for (String key : keysOf(user)) {
            DataType type = redis.type(key);
            Set<Object> members = type == DataType.SET ? redis.opsForSet().members(key)
                    : type == DataType.ZSET ? redis.opsForZSet().range(key, 0, -1) : Set.of();
            if (members != null) {
                members.forEach(member -> ids.add(member.toString()));
            }
        }
        return ids;
    }

    private static MockHttpServletRequest sessionRequest(String sessionId) {
        MockHttpSession session = new MockHttpSession(null, sessionId);
        session.setMaxInactiveInterval(1800);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return request;
    }

    private static Authentication hostAsserted(String userId) {
        return UsernamePasswordAuthenticationToken.authenticated(userId, null,
                AuthorityUtils.createAuthorityList("ROLE_AGENT"));
    }

    private static Authentication opaque(String userId) {
        Instant issuedAt = Instant.now();
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque-value",
                issuedAt, issuedAt.plus(Duration.ofHours(1)));
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(userId,
                Map.of("sub", userId), AuthorityUtils.createAuthorityList("SCOPE_reports.read"));
        return new BearerTokenAuthentication(principal, token, principal.getAuthorities());
    }

    private static Authentication jwt(String userId, String tokenId) {
        Instant issuedAt = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject(userId).jti(tokenId)
                .issuedAt(issuedAt).expiresAt(issuedAt.plus(Duration.ofHours(1))).build();
        return new JwtAuthenticationToken(jwt, AuthorityUtils.createAuthorityList("SCOPE_reports.read"));
    }
}
