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
package io.contexa.contexacommon.security.bridge.identity;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectResolver;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserEmailProvider;
import io.contexa.contexacommon.security.context.OfficialContextField;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The one function that makes the identity of a request (the legacy integration standard v2, sections 4, 5 and 10). */
@DisplayName("레거시 연동 표준 v2: 요청 신원 해석")
class IdentityResolutionTest {

    private static final ContexaSubject KIM = ContexaSubject.of("kim01", "kim01@seum.example").build();

    @Test
    @DisplayName("갈래 N: 리졸버가 이름 지은 사용자가 그 요청의 신원이 된다")
    void theResolversUserIsTheIdentity() {
        IdentityResolution resolution = resolution(request -> Optional.of(KIM), null, null);

        ContexaIdentity identity = resolution.resolve(new MockHttpServletRequest(), null);

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.RESOLVED);
        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.RESOLVER);
        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getProblems()).isEmpty();
    }

    @Test
    @DisplayName("갈래 N: 레거시 필터가 요청 속성에 넣은 사용자가 신원이 된다")
    void theRequestAttributesUserIsTheIdentity() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, KIM);

        ContexaIdentity identity = IdentityResolution.standard().resolve(request, null);

        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.REQUEST_ATTRIBUTE);
        assertThat(identity.getUserId()).isEqualTo("kim01");
    }

    @Test
    @DisplayName("아무도 이름 짓지 않으면 신원 없음이고 문제는 없다")
    void nobodyNamedIsAbsent() {
        ContexaIdentity identity = resolution(request -> Optional.empty(), null, null)
                .resolve(new MockHttpServletRequest(), null);

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.ABSENT);
        assertThat(identity.getProblems()).isEmpty();
    }

    @Test
    @DisplayName("리졸버가 예외를 던지면 잡아서 FAILED로 알리고, 다음 출처가 있으면 그것을 쓴다")
    void aFailingResolverIsCaught() {
        IdentityResolution resolution = resolution(request -> {
            throw new IllegalStateException("legacy session store is down");
        }, null, null);
        MockHttpServletRequest nothingElse = new MockHttpServletRequest();
        MockHttpServletRequest withAttribute = new MockHttpServletRequest();
        withAttribute.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, KIM);

        ContexaIdentity failed = resolution.resolve(nothingElse, null);
        ContexaIdentity fallback = resolution.resolve(withAttribute, null);

        assertThat(failed.getOutcome()).isEqualTo(ContexaIdentity.Outcome.FAILED);
        assertThat(failed.getProblems()).containsExactly(SubjectProblem.RESOLVER_FAILED);
        assertThat(fallback.getSource()).isEqualTo(ContexaIdentity.Source.REQUEST_ATTRIBUTE);
        assertThat(fallback.getProblems()).containsExactly(SubjectProblem.RESOLVER_FAILED);
        assertThat(resolution.diagnostics().snapshot().problems().get(SubjectProblem.RESOLVER_FAILED)).isEqualTo(2L);
    }

    @Test
    @DisplayName("리졸버가 아이디 규칙을 어긴 사용자를 주면 신원 없이 INVALID로 알린다")
    void aResolverUserBreakingTheRuleIsInvalid() {
        ContexaIdentity identity = resolution(request -> Optional.of(ContexaSubject.of(" ", "x@seum.example").build()),
                null, null).resolve(new MockHttpServletRequest(), null);

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.INVALID);
        assertThat(identity.getSubject()).isNull();
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.USER_ID_BLANK);
    }

    @Test
    @DisplayName("메일 없는 사용자도 신원은 성립하고 메일 결손이 표시된다")
    void aUserWithoutMailIsResolvedWithTheMailMissing() {
        ContexaIdentity identity = resolution(request -> Optional.of(ContexaSubject.of("kim01", null).build()), null, null)
                .resolve(new MockHttpServletRequest(), null);

        assertThat(identity.isResolved()).isTrue();
        assertThat(identity.isEmailMissing()).isTrue();
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.EMAIL_MISSING);
    }

    @Test
    @DisplayName("리졸버에 준 요청 보기는 세션을 만들지 않는다")
    void theResolverCreatesNoSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        IdentityResolution resolution = resolution(view -> view.sessionAttribute("loginVO")
                .map(found -> KIM), null, null);

        ContexaIdentity identity = resolution.resolve(request, null);

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.ABSENT);
        assertThat(request.getSession(false)).isNull();
    }

    @Test
    @DisplayName("리졸버는 세션 속성·헤더·컨테이너 사용자를 읽을 수 있다")
    void theResolverReadsTheSignInState() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute("loginVO", "kim01");
        request.addHeader("X-Login-Seq", "seq-7");
        request.setRemoteUser("container-kim");
        IdentityResolution resolution = resolution(view -> view.sessionAttribute("loginVO", String.class)
                .map(id -> ContexaSubject.of(id, id + "@seum.example")
                        .sessionKey(view.header("X-Login-Seq").orElse(null))
                        .displayName(view.remoteUser().orElse(null))
                        .build()), null, null);

        ContexaIdentity identity = resolution.resolve(request, null);

        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getSubject().getSessionKey()).isEqualTo("seq-7");
        assertThat(identity.getSubject().getDisplayName()).isEqualTo("container-kim");
    }

    @Test
    @DisplayName("제외 경로에서는 리졸버를 부르지 않는다")
    void theResolverIsNotCalledOnExcludedPaths() {
        AtomicInteger calls = new AtomicInteger();
        BridgeProperties properties = new BridgeProperties();
        properties.getResolver().setExcludePaths(List.of("/static/**"));
        IdentityResolution resolution = new IdentityResolution(IdentityResolution.Settings.of(properties), request -> {
            calls.incrementAndGet();
            return Optional.of(KIM);
        }, null, null, IdentityResolution.Accounts.NONE, new IdentityDiagnostics());
        MockHttpServletRequest asset = new MockHttpServletRequest("GET", "/static/app.css");
        asset.setServletPath("/static/app.css");
        MockHttpServletRequest page = new MockHttpServletRequest("GET", "/orders");
        page.setServletPath("/orders");

        assertThat(resolution.resolve(asset, null).getOutcome()).isEqualTo(ContexaIdentity.Outcome.ABSENT);
        assertThat(resolution.resolve(page, null).getUserId()).isEqualTo("kim01");
        assertThat(calls).hasValue(1);
    }

    @Test
    @DisplayName("기준보다 오래 걸린 리졸버는 알리되, 그 결과는 그대로 쓴다")
    void aSlowResolverIsReported() {
        BridgeProperties properties = new BridgeProperties();
        properties.getResolver().setSlowThreshold(Duration.ZERO);
        IdentityResolution resolution = new IdentityResolution(IdentityResolution.Settings.of(properties), request -> {
            long until = System.nanoTime() + 2_000_000L;
            while (System.nanoTime() < until) {
                Thread.onSpinWait();
            }
            return Optional.of(KIM);
        }, null, null, IdentityResolution.Accounts.NONE, new IdentityDiagnostics());

        ContexaIdentity identity = resolution.resolve(new MockHttpServletRequest(), null);

        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.RESOLVER_SLOW);
    }

    @Test
    @DisplayName("두 출처가 다른 사용자를 이름 지으면 순서상 먼저인 것을 쓰고 알린다")
    void twoSourcesNamingTwoUsersAreReported() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, ContexaSubject.of("lee02", "lee02@seum.example").build());

        ContexaIdentity identity = resolution(view -> Optional.of(KIM), null, null).resolve(request, null);

        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.RESOLVER);
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.SOURCES_DISAGREE);
    }

    @Test
    @DisplayName("요청 속성에 ContexaSubject가 아닌 값이 있으면 읽지 않고 알린다")
    void somethingElseUnderTheAttributeIsNotRead() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, "kim01");

        ContexaIdentity identity = IdentityResolution.standard().resolve(request, null);

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.INVALID);
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.NOT_A_SUBJECT);
    }

    @Test
    @DisplayName("갈래 S: 폼 로그인 사용자의 아이디는 getName(), 메일은 메일 공급자에서 읽는다")
    void aFormLoginUsersMailComesFromTheProvider() {
        Authentication form = UsernamePasswordAuthenticationToken.authenticated(
                User.withUsername("kim01").password("x").authorities("ROLE_USER").build(), null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        BridgeUserEmailProvider provider = userId -> userId + "@seum.example";

        ContexaIdentity identity = resolution(null, null, provider).resolve(new MockHttpServletRequest(), form);

        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.SPRING_SECURITY);
        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getSubject().getEmail()).isEqualTo("kim01@seum.example");
        assertThat(identity.getSubject().getAuthorities()).containsExactly("ROLE_USER");
        assertThat(identity.getAuthentication()).isSameAs(form);
    }

    @Test
    @DisplayName("갈래 S: 메일 공급자가 실패하면 메일 결손으로 두고 신원은 유지한다")
    void aFailingProviderLeavesTheMailMissing() {
        Authentication form = UsernamePasswordAuthenticationToken.authenticated("kim01", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        BridgeUserEmailProvider provider = userId -> {
            throw new IllegalStateException("directory down");
        };

        ContexaIdentity identity = resolution(null, null, provider).resolve(new MockHttpServletRequest(), form);

        assertThat(identity.isResolved()).isTrue();
        assertThat(identity.isEmailMissing()).isTrue();
        assertThat(identity.getProblems()).containsExactlyInAnyOrder(SubjectProblem.EMAIL_PROVIDER_FAILED,
                SubjectProblem.EMAIL_MISSING);
    }

    @Test
    @DisplayName("갈래 S: JWT의 email·sid·amr·auth_time·acr 클레임을 표준대로 읽는다")
    void aJwtUsersStandardClaimsAreRead() {
        Instant signedInAt = Instant.parse("2026-11-26T01:00:00Z");
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256")
                .subject("kim01")
                .claim("email", "kim01@seum.example")
                .claim("sid", "login-42")
                .claim("amr", List.of("pwd", "otp"))
                .claim("auth_time", signedInAt.getEpochSecond())
                .claim("acr", "AAL2")
                .build();
        JwtAuthenticationToken token = new JwtAuthenticationToken(jwt, AuthorityUtils.createAuthorityList("SCOPE_orders"));

        ContexaIdentity identity = IdentityResolution.standard().resolve(new MockHttpServletRequest(), token);

        ContexaSubject subject = identity.getSubject();
        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.SPRING_SECURITY);
        assertThat(subject.getUserId()).isEqualTo("kim01");
        assertThat(subject.getEmail()).isEqualTo("kim01@seum.example");
        assertThat(subject.getSessionKey()).isEqualTo("login-42");
        assertThat(subject.getAuthentication().getMfa()).isTrue();
        assertThat(subject.getAuthentication().getAuthenticatedAt()).isEqualTo(signedInAt);
        assertThat(subject.getAuthentication().getAssurance()).isEqualTo("AAL2");
    }

    @Test
    @DisplayName("갈래 S: OIDC 로그인 사용자의 메일은 읽되, id token의 sid는 세션 키로 쓰지 않는다(서블릿 세션 유지)")
    void anOidcLoginKeepsItsServletSession() {
        OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
                .subject("kim01")
                .claim("sid", "idp-session-7")
                .claim("email", "kim01@seum.example")
                .issuedAt(Instant.parse("2026-11-26T01:00:00Z"))
                .expiresAt(Instant.parse("2026-11-26T02:00:00Z"))
                .build();
        DefaultOidcUser user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("OIDC_USER"), idToken);
        OAuth2AuthenticationToken login = new OAuth2AuthenticationToken(user, user.getAuthorities(), "seum-idp");

        ContexaIdentity identity = IdentityResolution.standard().resolve(new MockHttpServletRequest(), login);

        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getSubject().getEmail()).isEqualTo("kim01@seum.example");
        assertThat(identity.getSubject().getSessionKey()).isNull();
    }

    @Test
    @DisplayName("갈래 S: 앱이 details에 둔 ContexaAuthentication을 로그인 사실로 읽는다")
    void theSignInFactsTheApplicationStatedAreRead() {
        UsernamePasswordAuthenticationToken form = UsernamePasswordAuthenticationToken.authenticated("kim01", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        form.setDetails(ContexaAuthentication.of("PASSWORD+OTP").mfa(true));

        ContexaIdentity identity = IdentityResolution.standard().resolve(new MockHttpServletRequest(), form);

        assertThat(identity.getSubject().getAuthentication().getMethod()).isEqualTo("PASSWORD+OTP");
        assertThat(identity.getSubject().getAuthentication().getMfa()).isTrue();
    }

    @Test
    @DisplayName("갈래 S: 접두사 있는 공식 맥락 속성만 로그인 사실로 읽고, 접두사 없는 앱 속성은 읽지 않는다")
    void onlyTheOfficialContextAttributesAreRead() {
        Authentication form = UsernamePasswordAuthenticationToken.authenticated("kim01", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        MockHttpServletRequest official = new MockHttpServletRequest();
        official.setAttribute(OfficialContextField.AUTHENTICATION_TYPE.canonicalAttributeKey(), "PASSWORD");
        official.setAttribute(OfficialContextField.MFA_VERIFIED.canonicalAttributeKey(), "true");
        MockHttpServletRequest applicationOwn = new MockHttpServletRequest();
        applicationOwn.setAttribute("authenticationType", "PASSWORD");
        applicationOwn.setAttribute("mfaVerified", Boolean.TRUE);

        ContexaAuthentication read = IdentityResolution.standard().resolve(official, form).getSubject().getAuthentication();
        ContexaAuthentication notRead = IdentityResolution.standard().resolve(applicationOwn, form).getSubject()
                .getAuthentication();

        assertThat(read.getMethod()).isEqualTo("PASSWORD");
        assertThat(read.getMfa()).isTrue();
        assertThat(notRead).isNull();
    }

    @Test
    @DisplayName("갈래 S: 앱 고유 principal 객체는 필드를 추측하지 않고 INVALID로 알린다")
    void anApplicationsOwnPrincipalIsNotGuessed() {
        Authentication own = UsernamePasswordAuthenticationToken.authenticated(new LegacyUser("kim01"), null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));

        ContexaIdentity identity = IdentityResolution.standard().resolve(new MockHttpServletRequest(), own);

        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.INVALID);
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.UNSUPPORTED_PRINCIPAL);
    }

    @Test
    @DisplayName("갈래 S: 매퍼가 있으면 앱 고유 principal을 매퍼가 이름 짓는다")
    void theMapperNamesAnApplicationsOwnPrincipal() {
        Authentication own = UsernamePasswordAuthenticationToken.authenticated(new LegacyUser("kim01"), null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        ContexaSubjectMapper mapper = authentication -> authentication.getPrincipal() instanceof LegacyUser user
                ? Optional.of(ContexaSubject.of(user.empNo(), user.empNo() + "@seum.example").build())
                : Optional.empty();

        ContexaIdentity identity = resolution(null, mapper, null).resolve(new MockHttpServletRequest(), own);

        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.SPRING_SECURITY);
        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(identity.getSubject().getEmail()).isEqualTo("kim01@seum.example");
    }

    @Test
    @DisplayName("갈래 S가 INVALID여도 리졸버가 이름 지으면 그 사용자를 쓴다(혼합 레거시)")
    void aResolverStandsInWhenSpringSecurityCannotName() {
        Authentication own = UsernamePasswordAuthenticationToken.authenticated(new LegacyUser("kim01"), null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));

        ContexaIdentity identity = resolution(view -> Optional.of(KIM), null, null)
                .resolve(new MockHttpServletRequest(), own);

        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.RESOLVER);
        assertThat(identity.getProblems()).containsExactly(SubjectProblem.UNSUPPORTED_PRINCIPAL);
    }

    @Test
    @DisplayName("Contexa 자체 계정은 CONTEXA_ACCOUNT 출처로 그 계정 이름을 쓴다")
    void oneOfContexasAccountsIsNamedByTheAccount() {
        Authentication admin = UsernamePasswordAuthenticationToken.authenticated("admin", null,
                AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
        IdentityResolution resolution = new IdentityResolution(IdentityResolution.Settings.defaults(), null, null, null,
                authentication -> "admin", new IdentityDiagnostics());

        ContexaIdentity identity = resolution.resolve(new MockHttpServletRequest(), admin);

        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.CONTEXA_ACCOUNT);
        assertThat(identity.getUserId()).isEqualTo("admin");
    }

    @Test
    @DisplayName("다시 해석할 때는 리졸버를 부르지 않는다(요청당 한 번)")
    void theResolverIsCalledOnceARequest() {
        AtomicInteger calls = new AtomicInteger();
        IdentityResolution resolution = resolution(view -> {
            calls.incrementAndGet();
            return Optional.of(KIM);
        }, null, null);
        MockHttpServletRequest request = new MockHttpServletRequest();

        resolution.resolve(request, null);
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, ContexaSubject.of("lee02", "lee02@seum.example").build());
        ContexaIdentity late = resolution.resolveAgainWithoutTheResolver(request, null);

        assertThat(calls).hasValue(1);
        assertThat(late.getUserId()).isEqualTo("lee02");
    }

    @Test
    @DisplayName("갈래 N: 메일 없이 이름 지은 사용자도 메일 공급자가 아는 메일을 받는다(두 갈래 같은 규칙)")
    void aResolverUserWithoutMailGetsTheProvidersMail() {
        BridgeUserEmailProvider provider = userId -> userId + "@seum.example";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, ContexaSubject.of("lee02", null).build());

        ContexaIdentity resolved = resolution(view -> Optional.of(ContexaSubject.of("kim01", null).build()), null, provider)
                .resolve(new MockHttpServletRequest(), null);
        ContexaIdentity attributed = resolution(null, null, provider).resolve(request, null);

        assertThat(resolved.getSubject().getEmail()).isEqualTo("kim01@seum.example");
        assertThat(resolved.getProblems()).isEmpty();
        assertThat(attributed.getSubject().getEmail()).isEqualTo("lee02@seum.example");
    }

    @Test
    @DisplayName("메일 출처에 공급자가 없으면 갈래 N 사용자에게도 공급자를 부르지 않는다")
    void theProviderIsNotAskedWhenTheMailSourcesLeaveItOut() {
        AtomicInteger asked = new AtomicInteger();
        BridgeProperties properties = new BridgeProperties();
        properties.setEmailSources(List.of("claim:email"));
        IdentityResolution resolution = new IdentityResolution(IdentityResolution.Settings.of(properties),
                view -> Optional.of(ContexaSubject.of("kim01", null).build()), null, userId -> {
                    asked.incrementAndGet();
                    return userId + "@seum.example";
                }, IdentityResolution.Accounts.NONE, new IdentityDiagnostics());

        ContexaIdentity identity = resolution.resolve(new MockHttpServletRequest(), null);

        assertThat(identity.isEmailMissing()).isTrue();
        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("알 수 없는 출처 이름이나 빈 출처 목록은 기동을 멈추고 설정할 것을 알린다")
    void unknownSourcesStopTheStart() {
        BridgeProperties unknown = new BridgeProperties();
        unknown.setIdentitySources(List.of("spring-security", "session"));
        BridgeProperties none = new BridgeProperties();
        none.setIdentitySources(List.of());
        BridgeProperties unknownMail = new BridgeProperties();
        unknownMail.setEmailSources(List.of("ldap"));

        assertThatThrownBy(() -> IdentityResolution.Settings.of(unknown))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("session");
        assertThatThrownBy(() -> IdentityResolution.Settings.of(none))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("names no source");
        assertThatThrownBy(() -> IdentityResolution.Settings.of(unknownMail))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("ldap");
    }

    @Test
    @DisplayName("기본 출처 순서는 spring-security, resolver, request-attribute다")
    void theDefaultOrder() {
        assertThat(IdentityResolution.Settings.defaults().order()).containsExactly(ContexaIdentity.Source.SPRING_SECURITY,
                ContexaIdentity.Source.RESOLVER, ContexaIdentity.Source.REQUEST_ATTRIBUTE);
        assertThat(IdentityResolution.Settings.defaults().emailSources()).containsExactly("claim:email", "provider");
    }

    private static IdentityResolution resolution(ContexaSubjectResolver resolver, ContexaSubjectMapper mapper,
                                                 BridgeUserEmailProvider provider) {
        return new IdentityResolution(IdentityResolution.Settings.defaults(), resolver, mapper, provider,
                IdentityResolution.Accounts.NONE, new IdentityDiagnostics());
    }

    /** An application's own principal object, of none of the kinds Spring Security names a user by. */
    private record LegacyUser(String empNo) {
    }
}
