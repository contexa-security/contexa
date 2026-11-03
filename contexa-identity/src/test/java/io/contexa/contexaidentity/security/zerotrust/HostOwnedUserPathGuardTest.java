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
package io.contexa.contexaidentity.security.zerotrust;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

class HostOwnedUserPathGuardTest {

    private final HostOwnedUserPathGuard guard = new HostOwnedUserPathGuard();

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("an anonymous request to the user's Contexa pages gets 401, even where the application lets all in")
    void anonymousGets401() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(new MockHttpServletRequest("GET", "/contexa/api/agent-delegations"), response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    @DisplayName("the signed-in user of the application goes on, with the authentication untouched")
    void signedInGoesOn() throws Exception {
        TestingAuthenticationToken user = new TestingAuthenticationToken("alice", null, "ROLE_USER");
        SecurityContextHolder.getContext().setAuthentication(user);
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(new MockHttpServletRequest("GET", "/contexa/step-up"), new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(user);
    }

    /**
     * Docs review 2026-11-03: the block screen asks for the release of a block and the analysis-pending screen follows
     * its analysis under /contexa/admin/api/aiam, which the console chain kept for administrators, so a blocked user of
     * the application could not ask for the release. They are the user's paths, as in Contexa's own chain.
     */
    @Test
    @DisplayName("the block release and the pending analysis are the user's paths, not the console's")
    void selfServicePathsAreTheUsers() {
        assertThat(HostOwnedUserPathGuard.ADMIN_SELF_SERVICE_PREFIXES)
                .containsExactly("/contexa/admin/api/aiam/zero-trust", "/contexa/admin/api/aiam/sse/zero-trust");
        assertThat(HostOwnedUserPathGuard.URL_PATTERNS)
                .contains("/contexa/admin/api/aiam/zero-trust/*", "/contexa/admin/api/aiam/sse/zero-trust/*");
    }
}
