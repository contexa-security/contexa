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

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * bridge v2 step B4: the subject of an authentication is its name as Spring Security gives it, for the kinds Spring
 * Security names a user by. An application's own principal object is not read field by field (the guess of analysis A-3
 * is gone); it names no subject, and the application maps it with a {@code ContexaSubjectMapper}.
 */
@DisplayName("레거시 연동 표준 v2: 인증의 주체 ID는 Spring 표준 종류의 이름이고, 앱 고유 객체는 추측하지 않는다")
class ContexaIdentitySubjectTest {

    /** An application's object put in an authentication as its principal, with no name of Spring Security's kinds. */
    static final class LoginUser {
        private final String userId;

        LoginUser(String userId) {
            this.userId = userId;
        }

        public String getUserId() {
            return userId;
        }
    }

    private static UsernamePasswordAuthenticationToken signedIn(Object principal) {
        return new UsernamePasswordAuthenticationToken(principal, null, AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    @Test
    @DisplayName("앱 고유 객체 principal은 필드를 읽지 않으므로 주체가 없다(매퍼가 이름 짓는다)")
    void aPlainObjectPrincipalNamesNoSubject() {
        assertThat(ContexaIdentity.subjectId(signedIn(new LoginUser("E1001")))).isNull();
    }

    @Test
    @DisplayName("Map principal도 키를 읽지 않으므로 주체가 없다")
    void aMapPrincipalNamesNoSubject() {
        assertThat(ContexaIdentity.subjectId(signedIn(Map.of("userId", "kim", "deptCd", "D01")))).isNull();
    }

    @Test
    @DisplayName("UserDetails와 문자열 principal은 Spring의 이름 그대로다")
    void aUserDetailsOrATextPrincipalKeepsSpringsName() {
        User details = new User("alice", "x", AuthorityUtils.createAuthorityList("ROLE_USER"));

        assertThat(ContexaIdentity.subjectId(signedIn(details))).isEqualTo("alice");
        assertThat(ContexaIdentity.subjectId(signedIn("  bob  "))).isEqualTo("bob");
    }
}
