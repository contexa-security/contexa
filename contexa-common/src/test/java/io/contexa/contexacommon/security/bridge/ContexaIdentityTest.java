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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: the user Contexa decides a request for. The application's signed-in user
 * comes first; without one, the user the bridge resolved for Contexa alone; never the application's security context
 * written by Contexa.
 */
@DisplayName("Contexa 판정 신원(R-10)")
class ContexaIdentityTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("앱이 로그인시킨 사용자가 있으면 그 사용자로 판정한다")
    void theApplicationsUserComesFirst() {
        Authentication application = UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(application);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.IDENTITY, signedIn("bob"));

        assertThat(ContexaIdentity.of(request)).isSameAs(application);
    }

    @Test
    @DisplayName("앱 사용자가 익명이면 bridge가 Contexa만을 위해 해석한 신원으로 판정한다")
    void theBridgedUserStandsInForAnAnonymousRequest() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        Authentication bridged = signedIn("bob");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.IDENTITY, bridged);

        assertThat(ContexaIdentity.of(request)).isSameAs(bridged);
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("the application's security context is not changed")
                .isInstanceOf(AnonymousAuthenticationToken.class);
    }

    @Test
    @DisplayName("해석한 신원이 없으면 앱의 보안 문맥을 그대로 돌려준다")
    void withoutAnyUserTheContextIsGivenBackAsItIs() {
        AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        SecurityContextHolder.getContext().setAuthentication(anonymous);

        assertThat(ContexaIdentity.of(new MockHttpServletRequest())).isSameAs(anonymous);
        assertThat(ContexaIdentity.of(null)).isSameAs(anonymous);
        SecurityContextHolder.clearContext();
        assertThat(ContexaIdentity.of(new MockHttpServletRequest())).isNull();
    }

    @Test
    @DisplayName("주체 ID는 하나의 규칙이다: 인증의 이름(getName)을 다듬은 값")
    void theSubjectIdIsTheNameOfTheAuthentication() {
        assertThat(ContexaIdentity.subjectId(signedIn(" alice "))).isEqualTo("alice");
        assertThat(ContexaIdentity.subjectId(signedIn(" "))).isNull();
        assertThat(ContexaIdentity.subjectId(null)).isNull();
    }

    @Test
    @DisplayName("요청의 사용자 ID는 Contexa가 해석한 신원이 먼저다(매퍼·리졸버가 이름 지은 사용자)")
    void theUserIdOfARequestIsTheResolvedIdentitys() {
        SecurityContextHolder.getContext().setAuthentication(signedIn("alice"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, ContexaIdentity.resolved(
                ContexaSubject.of("E1001", "e1001@seum.example").sessionKey("login-9").build(),
                ContexaIdentity.Source.SPRING_SECURITY, List.of(), null));

        assertThat(ContexaIdentity.userId(request)).isEqualTo("E1001");
        assertThat(ContexaIdentity.sessionKey(request)).isEqualTo("login-9");
    }

    @Test
    @DisplayName("해석한 신원이 없거나 성립하지 않았으면 요청 인증의 주체 ID를 쓴다")
    void withoutAResolvedIdentityTheAuthenticationNamesTheUser() {
        SecurityContextHolder.getContext().setAuthentication(signedIn("alice"));
        MockHttpServletRequest unseen = new MockHttpServletRequest();
        MockHttpServletRequest unresolved = new MockHttpServletRequest();
        unresolved.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, ContexaIdentity.absent());

        assertThat(ContexaIdentity.userId(unseen)).isEqualTo("alice");
        assertThat(ContexaIdentity.userId(unresolved)).isEqualTo("alice");
        assertThat(ContexaIdentity.sessionKey(unresolved)).isNull();
        assertThat(ContexaIdentity.userId(null)).isEqualTo("alice");
    }

    @Test
    @DisplayName("넘겨받은 주체로 정할 때도 해석한 신원이 먼저이고, 없으면 인증의 주체·컨테이너 사용자의 표준 이름을 쓰며 익명은 사용자가 아니다")
    void theUserIdWithAPrincipalStandingIn() {
        MockHttpServletRequest resolved = new MockHttpServletRequest();
        resolved.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, ContexaIdentity.resolved(
                ContexaSubject.of("E1001", "e1001@seum.example").build(), ContexaIdentity.Source.RESOLVER, List.of(), null));
        MockHttpServletRequest unseen = new MockHttpServletRequest();
        AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertThat(ContexaIdentity.userId(resolved, signedIn("alice"))).isEqualTo("E1001");
        assertThat(ContexaIdentity.userId(unseen, signedIn(" alice "))).isEqualTo("alice");
        assertThat(ContexaIdentity.userId(unseen, () -> " container-kim ")).isEqualTo("container-kim");
        assertThat(ContexaIdentity.userId(unseen, anonymous)).isNull();
        assertThat(ContexaIdentity.userId(unseen, null)).isNull();
    }

    private static Authentication signedIn(String name) {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken(name, null, "ROLE_USER");
        authentication.setAuthenticated(true);
        return authentication;
    }
}
