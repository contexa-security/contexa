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
package io.contexa.autoconfigure.iam.admin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;

class HostOwnedAdminConsoleRequestsTest {

    private final RequestMatcher console = HostOwnedAdminConsoleAutoConfiguration.consoleRequests();

    private boolean takes(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        return console.matches(request);
    }

    /**
     * Docs review 2026-11-03: the console chain took /contexa/admin/** whole, so the block screen's release request and
     * the analysis-pending screen's updates (the user's paths under /contexa/admin/api/aiam) asked for an administrator.
     */
    @Test
    @DisplayName("the console chain takes the console, and leaves the user's block release and pending analysis")
    void takesTheConsoleOnly() {
        assertThat(takes("GET", "/contexa/admin")).isTrue();
        assertThat(takes("GET", "/contexa/admin/dashboard")).isTrue();
        assertThat(takes("GET", "/contexa/admin/api/agents")).isTrue();
        assertThat(takes("POST", "/contexa/admin/login")).isTrue();

        assertThat(takes("POST", "/contexa/admin/api/aiam/zero-trust/initiate-block-mfa")).isFalse();
        assertThat(takes("POST", "/contexa/admin/api/aiam/zero-trust/unblock-request")).isFalse();
        assertThat(takes("GET", "/contexa/admin/api/aiam/sse/zero-trust/subscribe")).isFalse();
        assertThat(takes("GET", "/page")).isFalse();
    }

    /** Left to the application's chain, a sign-in page lost its look and the password change stood without the console's CSRF. */
    @Test
    @DisplayName("the console chain also takes what the console needs before sign-in, and nothing of the application's")
    void takesWhatTheConsoleNeedsBeforeSignIn() {
        assertThat(takes("GET", "/contexa/css/console.css")).isTrue();
        assertThat(takes("GET", "/contexa/js/contexa-mfa-sdk.js")).isTrue();
        assertThat(takes("GET", "/contexa/img/logo.svg")).isTrue();
        assertThat(takes("GET", "/contexa/password-change")).isTrue();
        assertThat(takes("POST", "/contexa/password-change")).isTrue();

        assertThat(takes("GET", "/css/site.css")).isFalse();
        assertThat(takes("GET", "/password-change")).isFalse();
    }
}
