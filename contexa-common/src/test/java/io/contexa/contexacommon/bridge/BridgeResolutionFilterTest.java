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

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.authentication.HostPrincipalSnapshot;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * The stamps the bridge filter makes for a signed-in Spring Security user, from the resolvers the auto-configuration
 * registers and the ones an application adds. bridge v2 B6: the session, request attribute and header channels and the
 * explicit handoff are gone, so their cases left this test; what they shared with the remaining resolvers (the derived
 * authorization, the token's delegation, the merging of authorization evidence, the copy of the user) stays.
 */
class BridgeResolutionFilterTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("명시적 인가 사실이 없으면 인증의 권한에서 인가 도장을 유도하고, 앱 보안 문맥은 그대로 둔다")
    void shouldDeriveAuthorizationStampFromAuthenticationAuthoritiesWhenExplicitAuthorizationIsMissing() throws Exception {
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                new BridgeProperties(),
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(),
                List.of(),
                new BridgeCoverageEvaluator());
        Authentication hostAuthentication = authenticateHost("alice", "ROLE_USER", "REPORT_EXPORT");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("AUTHENTICATION_DERIVED");
        assertThat(result.authorizationStamp().effect().name()).isEqualTo("UNKNOWN");
        assertThat(result.authorizationStamp().effectiveRoles()).contains("ROLE_USER");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("ROLE_USER", "REPORT_EXPORT");
        assertThat(result.authorizationStamp().privileged()).isNull();
        assertThat(result.authorizationStamp().attributes())
                .containsEntry("authorizationEvidenceState", "DERIVED_RUNTIME_FALLBACK");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(result.coverageReport().missingContexts()).contains(MissingBridgeContext.AUTHORIZATION_EFFECT);
        assertThat(result.coverageReport().summary()).contains("Bridge completeness reached authentication");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    /**
     * A1-1: a host's own resource server validated the token (Contexa does not own the chain); the delegation the
     * token states is taken, since the authorization server signed it.
     */
    @Test
    @DisplayName("호스트가 검증한 토큰이 밝힌 위임을 위임 도장으로 쓴다")
    void shouldTakeTheDelegationAHostValidatedTokenStates() throws Exception {
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                new BridgeProperties(),
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(new TokenDelegationStampResolver()),
                new BridgeCoverageEvaluator());
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(
                Jwt.withTokenValue("header.payload.signature")
                        .header("alg", "RS256")
                        .claim("sub", "alice")
                        .claim("act", Map.of("sub", "agent-7"))
                        .issuedAt(Instant.parse("2026-10-21T09:00:00Z"))
                        .expiresAt(Instant.parse("2026-10-21T10:00:00Z"))
                        .build(),
                AuthorityUtils.createAuthorityList("SCOPE_reports.read")));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result.delegationStamp()).isNotNull();
        assertThat(result.delegationStamp().agentId()).isEqualTo("agent-7");
        assertThat(result.delegationStamp().subjectId()).isEqualTo("alice");
        assertThat(result.delegationStamp().delegated()).isTrue();
        assertThat(result.delegationStamp().attributes()).containsEntry("delegationResolver", "TOKEN");
    }

    @Test
    @DisplayName("앱이 더한 인가 해석기의 명시적 DENY가 보안 문맥의 UNKNOWN보다 먼저 쓰이고 근거 출처가 함께 남는다")
    void shouldPreferAnExplicitDenyOfAnotherResolverOverTheSecurityContextsUnknown() throws Exception {
        BridgeResolutionFilter filter = createSecurityContextAndApplicationFilter("app-deny-policy");
        Authentication hostAuthentication = authenticateHost("alice", "ROLE_HOST");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result.authorizationStamp().effect().name()).isEqualTo("DENY");
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("APPLICATION");
        assertThat(result.authorizationStamp().policyId()).isEqualTo("app-deny-policy");
        assertThat(result.authorizationStamp().attributes().get("authorizationEvidenceSources"))
                .isEqualTo(List.of("SECURITY_CONTEXT", "APPLICATION"));
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    @DisplayName("두 인가 근거의 명시적 효과가 부딪히면 DENY로 안전하게 정하고 충돌을 기록한다")
    void shouldFailSafeToDenyWhenExplicitAuthorizationEffectsConflict() throws Exception {
        BridgeResolutionFilter filter = createSecurityContextAndApplicationFilter("app-deny-policy");
        Authentication hostAuthentication = authenticateHost("alice", "ROLE_HOST");
        ((UsernamePasswordAuthenticationToken) hostAuthentication).setDetails(Map.of(
                "authorizationEffect", "ALLOW",
                "policyId", "host-allow-policy"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result.authorizationStamp().effect().name()).isEqualTo("DENY");
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("CONFLICT_FAIL_SAFE");
        assertThat(result.authorizationStamp().policyId()).isEqualTo("app-deny-policy");
        assertThat(result.authorizationStamp().attributes())
                .containsEntry("authorizationConflict", true)
                .containsEntry("authorizationConflictResolution", "DENY_FAIL_SAFE");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    void shouldResolveExistingHostAuthenticationWithoutHeaderContract() throws Exception {
        BridgeResolutionFilter filter = createSecurityContextFilter();
        Authentication hostAuthentication = authenticateHost("alice", "ROLE_USER", "REPORT_EXPORT");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("10.0.0.10");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        var hostSnapshot = (HostPrincipalSnapshot)
                request.getAttribute(BridgeRequestAttributes.HOST_PRINCIPAL_SNAPSHOT);
        assertThat(hostSnapshot.principalId()).isEqualTo("alice");
        assertThat(hostSnapshot.authorities()).containsExactlyInAnyOrder("ROLE_USER", "REPORT_EXPORT");
        assertThat(hostSnapshot.trustedAttributes()).containsEntry("authenticated", true);
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("alice");
        assertThat(result.authenticationStamp().authenticationType()).isEqualTo("UsernamePasswordAuthenticationToken");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("SECURITY_CONTEXT");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("REPORT_EXPORT");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(result.coverageReport().summary()).contains("Bridge completeness reached authentication");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    @DisplayName("로그인이 만든 사용자 사본의 동기화 결과가 그 뒤 요청에 실리고, 앱 보안 문맥은 그대로다")
    void shouldProjectTheUserSyncResultOfTheSignInIntoTheRequestAfterIt() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator(),
                (authenticationStamp, authorizationStamp, requestContext) -> new BridgeUserMirrorSyncResult(
                        77L,
                        "brg_sync_user",
                        authenticationStamp.principalId(),
                        "brg_subject_key",
                        true,
                        true,
                        true,
                        true
                )
        );

        Authentication hostAuthentication = authenticateHost("alice", "ROLE_HOST");
        MockHttpServletRequest signIn = new MockHttpServletRequest("POST", "/reports/export");
        filter.resolveSignIn(signIn, hostAuthentication);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeUserMirrorSyncResult syncResult =
                (BridgeUserMirrorSyncResult) request.getAttribute(BridgeRequestAttributes.USER_SYNC_RESULT);
        assertThat(syncResult).isNotNull();
        assertThat(syncResult.internalUserId()).isEqualTo(77L);
        assertThat(syncResult.internalUsername()).isEqualTo("brg_sync_user");
        assertThat(syncResult.bridgeSubjectKey()).isEqualTo("brg_subject_key");
        assertThat(syncResult.externalSubjectId()).isEqualTo("alice");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    @DisplayName("보안 문맥의 JWT 사용자를 그 이름으로 도장 찍고, 사본 동기화는 요청 밖에서 한 번 한다")
    void shouldResolveTheSecurityContextJwtAndSynchroniseItsUserOnce() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        AtomicInteger filterSyncCalls = new AtomicInteger();
        BridgeResolutionFilter filter = createSecurityContextFilter(properties, countingMirrorSync(filterSyncCalls));
        authenticateJwt("u-100", "a@corp.com");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        AuthenticationStamp stamp = result.authenticationStamp();
        assertThat(stamp.principalId()).isEqualTo("u-100");
        assertThat(stamp.authenticationSource()).isEqualTo("SECURITY_CONTEXT");
        awaitSyncCalls(filterSyncCalls, 1);
    }

    /**
     * The Spring Security resolvers, and after them an authorization resolver the application registers, which states
     * an explicit DENY under a policy of its own.
     */
    private BridgeResolutionFilter createSecurityContextAndApplicationFilter(String policyId) {
        AuthorizationStampResolver application = (request, requestContext, properties) -> Optional.of(new AuthorizationStamp(
                "alice",
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.DENY,
                false,
                List.of(),
                policyId,
                "1",
                "APPLICATION",
                Instant.now(),
                List.of("ROLE_USER"),
                List.of("REPORT_EXPORT"),
                Map.of()));
        return new BridgeResolutionFilter(
                new BridgeProperties(),
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver(), application),
                List.of(),
                new BridgeCoverageEvaluator()
        );
    }

    private BridgeResolutionFilter createSecurityContextFilter() {
        BridgeProperties properties = new BridgeProperties();
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator()
        );
    }

    private BridgeResolutionFilter createSecurityContextFilter(
            BridgeProperties properties,
            BridgeUserMirrorSyncService bridgeUserMirrorSyncService) {
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator(),
                bridgeUserMirrorSyncService,
                new BridgeRuntimeSupport(properties, bridgeUserMirrorSyncService),
                null
        );
    }

    /** The request does not wait for the copy: its synchronisation runs away from it, once. */
    private static void awaitSyncCalls(AtomicInteger calls, int expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (calls.get() < expected && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        Thread.sleep(50);
        assertThat(calls).hasValue(expected);
    }

    private BridgeUserMirrorSyncService countingMirrorSync(AtomicInteger calls) {
        return (authenticationStamp, authorizationStamp, requestContext) -> {
            calls.incrementAndGet();
            return null;
        };
    }

    private Authentication authenticateJwt(String subject, String email) {
        Jwt jwt = Jwt.withTokenValue("header.payload.signature")
                .header("alg", "RS256")
                .claim("sub", subject)
                .claim("email", email)
                .build();
        Authentication authentication = new JwtAuthenticationToken(jwt, AuthorityUtils.createAuthorityList("SCOPE_reports"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    private Authentication authenticateHost(String username, String... authorities) {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                username,
                "n/a",
                AuthorityUtils.createAuthorityList(authorities)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }
}
