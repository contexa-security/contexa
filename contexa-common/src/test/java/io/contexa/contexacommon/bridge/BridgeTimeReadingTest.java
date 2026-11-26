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
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeInstants;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.identity.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One reading of a time the application gives the bridge, whichever way it came: an instant, seconds or milliseconds since
 * the epoch (as a number or as digits), ISO-8601 text. An authentication time ahead of this server's clock is no fact of
 * the past: the stamp does not use it, and keeps what it ignored. It refuses nothing of the request. bridge v2 B6: the
 * times are read from the signed-in Spring Security user, the one place of the application's that the stamps still read;
 * the old handoff, session and request attribute channels are gone.
 */
class BridgeTimeReadingTest {

    /** 2026-03-20T09:53:20Z in seconds since the epoch. */
    private static final long EPOCH_SECONDS = 1_774_000_400L;
    private static final Instant IN_SECONDS = Instant.ofEpochSecond(EPOCH_SECONDS);
    /** The time of a sign-in in the form legacy systems keep (yyyyMMddHHmmss); read as milliseconds it lies in 2612. */
    private static final String LEGACY_DIGITS = "20261125103000";
    private static final String IGNORED = BridgeInstants.IGNORED_FUTURE_AUTHENTICATION_TIME;

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("보안 문맥의 인증 시각이 epoch 초이면 1970년이 아니라 그 시각으로 읽는다")
    void aSecurityContextSignInInSecondsSinceTheEpochIsThatTime() {
        signIn(Map.of("authenticationTime", EPOCH_SECONDS));

        assertThat(stamp().authenticationTime()).isEqualTo(IN_SECONDS);
        assertThat(BridgeObjectExtractor.extractInstant(Map.of("t", EPOCH_SECONDS), List.of("t"))).isEqualTo(IN_SECONDS);
    }

    @Test
    @DisplayName("보안 문맥의 로그인 시각이 레거시 형식 숫자로 서버 시계보다 미래이면 판정에 쓰지 않고 무시한 값을 기록하며 요청은 막지 않는다")
    void aSecurityContextSignInInLegacyDigitsAheadOfTheClockIsNotUsedAndIsKept() {
        signIn(Map.of("loginTime", LEGACY_DIGITS));

        AuthenticationStamp stamp = stamp();

        assertThat(stamp.principalId()).isEqualTo("alice");
        assertThat(stamp.authenticationTime()).isNull();
        assertThat(stamp.attributes()).containsEntry("authenticationTimeEvidenceState", BridgeSemanticBoundaryPolicy.UNAVAILABLE);
        assertThat(stamp.attributes()).containsKey(IGNORED);
    }

    @Test
    @DisplayName("보안 문맥의 인증 시각이 미래이면 판정에 쓰지 않는다")
    void aSecurityContextSignInAheadOfTheClockIsNotUsed() {
        signIn(Map.of("authenticationTime", "2612-11-25T10:30:00Z"));

        AuthenticationStamp stamp = stamp();

        assertThat(stamp.authenticationTime()).isNull();
        assertThat(stamp.attributes()).containsEntry("authenticationTimeEvidenceState", BridgeSemanticBoundaryPolicy.UNAVAILABLE);
        assertThat(stamp.attributes()).containsKey(IGNORED);
        assertThat(stamp.attributes().get("authenticationTime")).isNull();
    }

    @Test
    @DisplayName("시계 차이 안쪽의 인증 시각은 그대로 쓴다")
    void aSignInWithinTheClockSkewIsUsed() {
        Instant justAhead = Instant.now().plusSeconds(5);
        signIn(Map.of("authenticationTime", justAhead));

        AuthenticationStamp stamp = stamp();

        assertThat(stamp.authenticationTime()).isEqualTo(justAhead);
        assertThat(stamp.attributes()).doesNotContainKey(IGNORED);
    }

    private static void signIn(Map<String, Object> details) {
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_USER"));
        authentication.setDetails(details);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private static AuthenticationStamp stamp() {
        return new SecurityContextAuthenticationStampResolver()
                .resolve(new MockHttpServletRequest(), snapshot(), new BridgeProperties()).orElseThrow();
    }

    private static RequestContextSnapshot snapshot() {
        return new RequestContextSnapshot("/orders", "GET", "10.0.0.10", "JUnit", "s-1", "r-1", "/orders", null, false,
                Instant.now());
    }
}
