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
package io.contexa.contexacommon.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/** Ownership design S-7: a user the application signs in only after Contexa's request filters is reported. */
class HostOwnedIdentityNoticeTest {

    @Test
    @DisplayName("a user known at the protected method but not at the request filters is a late sign-in")
    void lateSignInIsRecognised() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HostOwnedIdentityNotice.markWhenNoUser(request, new AnonymousAuthenticationToken("k", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertThat(HostOwnedIdentityNotice.isLateSignIn(request, new TestingAuthenticationToken("alice", null, "ROLE_USER")))
                .isTrue();
    }

    @Test
    @DisplayName("a user the request filters already saw, and an anonymous call, are not late sign-ins")
    void notLate() {
        MockHttpServletRequest seen = new MockHttpServletRequest();
        HostOwnedIdentityNotice.markWhenNoUser(seen, new TestingAuthenticationToken("alice", null, "ROLE_USER"));
        assertThat(HostOwnedIdentityNotice.isLateSignIn(seen, new TestingAuthenticationToken("alice", null, "ROLE_USER")))
                .isFalse();

        MockHttpServletRequest anonymous = new MockHttpServletRequest();
        HostOwnedIdentityNotice.markWhenNoUser(anonymous, null);
        assertThat(HostOwnedIdentityNotice.isLateSignIn(anonymous, new AnonymousAuthenticationToken("k",
                "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")))).isFalse();
    }
}
