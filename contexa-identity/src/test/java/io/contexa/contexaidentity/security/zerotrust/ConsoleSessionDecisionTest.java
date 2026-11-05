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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** Q-17 (PR-67): the application's user and the console's administrator of one name are two people. */
class ConsoleSessionDecisionTest {

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(actions,
            mock(AuthResponseWriter.class), mock(IBlockedUserRecorder.class), null, mock(AuthUrlProvider.class), null, 2);

    @BeforeEach
    void anAdministrator() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("rcboss", "x", "ROLE_ADMIN"));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    private void blocked(String key) {
        actions.saveAction(key, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(key);
    }

    private MockHttpServletResponse request(String path, boolean console) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        if (console) {
            ConsoleSession.mark(request);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        passed = chain.getRequest() != null;
        return response;
    }

    private boolean passed;

    @Test
    @DisplayName("the BLOCK of the application's user leaves the console open to the administrator of that name")
    void anApplicationBlockLeavesTheConsoleOpen() throws Exception {
        blocked("rcboss");

        request("/contexa/admin/users", true);

        assertThat(passed).isTrue();
    }

    @Test
    @DisplayName("the application's own request of that name stays blocked")
    void theApplicationUserStaysBlocked() throws Exception {
        blocked("rcboss");

        MockHttpServletResponse response = request("/orders", false);

        assertThat(passed).isFalse();
        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/zero-trust/blocked");
    }

    @Test
    @DisplayName("a BLOCK of the console session stops the console, and sends it where a block is lifted")
    void aConsoleBlockStopsTheConsole() throws Exception {
        blocked("console::rcboss");

        MockHttpServletResponse response = request("/contexa/admin/users", true);

        assertThat(passed).isFalse();
        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/blacklist");
    }

    @Test
    @DisplayName("the block list stays open to a console session whatever is decided about it")
    void theReleasePathStaysOpen() throws Exception {
        blocked("console::rcboss");

        request("/contexa/admin/blacklist", true);
        assertThat(passed).isTrue();

        request("/contexa/admin/api/blacklist/1/resolve", true);
        assertThat(passed).isTrue();
    }

    @Test
    @DisplayName("a request of the application's chain gets no such path: the path alone opens nothing")
    void thePathAloneOpensNothing() throws Exception {
        blocked("rcboss");

        request("/contexa/admin/blacklist", false);

        assertThat(passed).isFalse();
    }
}
