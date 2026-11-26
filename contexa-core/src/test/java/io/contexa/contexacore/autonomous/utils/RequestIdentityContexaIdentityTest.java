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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
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
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: the user of a request, as the engine's events record it, is the one
 * Contexa decides for: the application's signed-in user, else the user the bridge resolved for Contexa alone.
 */
@DisplayName("요청의 사용자는 Contexa 판정 신원이다(R-10)")
class RequestIdentityContexaIdentityTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Spring 인증이 없으면 bridge가 해석한 신원이 요청의 사용자다")
    void theBridgedUserIsTheUserOfTheRequest() {
        TestingAuthenticationToken bridged = new TestingAuthenticationToken("u-100", null, "ROLE_USER");
        bridged.setAuthenticated(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.IDENTITY, bridged);

        assertThat(RequestIdentity.userId(request)).isEqualTo("u-100");
    }

    @Test
    @DisplayName("앱이 로그인시킨 사용자가 있으면 그 사용자가 요청의 사용자다")
    void theApplicationsUserComesFirst() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));
        TestingAuthenticationToken bridged = new TestingAuthenticationToken("u-100", null, "ROLE_USER");
        bridged.setAuthenticated(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.IDENTITY, bridged);

        assertThat(RequestIdentity.userId(request)).isEqualTo("alice");
    }

    @Test
    @DisplayName("bridge가 해석한 신원이 성립했으면 그 사용자 ID가 요청의 사용자다(앱 매퍼가 정한 ID)")
    void theResolvedIdentitysUserIsTheUserOfTheRequest() {
        Authentication alice = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(alice);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, ContexaIdentity.resolved(
                ContexaSubject.of("emp-7", "emp7@seum.example").build(), ContexaIdentity.Source.SPRING_SECURITY,
                Set.of(), alice));

        assertThat(RequestIdentity.userId(request)).isEqualTo("emp-7");
    }

    @Test
    @DisplayName("성립하지 않은 신원은 앱이 로그인시킨 사용자를 가리지 않는다")
    void anUnresolvedIdentityLeavesTheApplicationsUser() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, ContexaIdentity.unresolved(
                ContexaIdentity.Outcome.FAILED, Set.of(SubjectProblem.MAPPER_FAILED)));

        assertThat(RequestIdentity.userId(request)).isEqualTo("alice");
    }

    @Test
    @DisplayName("앱 고유 principal 객체는 필드를 추측하지 않으므로 요청의 사용자가 없다")
    void anApplicationsOwnPrincipalNamesNoUser() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(new LegacyLoginUser("kim01"), null, List.of()));

        assertThat(RequestIdentity.userId(new MockHttpServletRequest())).isNull();
    }

    @Test
    @DisplayName("익명 방문자는 요청의 사용자가 아니다")
    void anAnonymousVisitorIsNoUserOfTheRequest() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertThat(RequestIdentity.userId(new MockHttpServletRequest())).isNull();
    }

    /** A legacy application's own login object, of none of the kinds Spring Security names a user by. */
    private static final class LegacyLoginUser {

        private final String empNo;

        private LegacyLoginUser(String empNo) {
            this.empNo = empNo;
        }

        String getEmpNo() {
            return empNo;
        }
    }
}
