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
package io.contexa.contexaiam.aiam.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.socket.WebSocketHandler;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** The connection of the console's live screens is opened for a signed-in user only. */
class AuthenticatedHandshakeInterceptorTest {

    private final WebSocketConfig.AuthenticatedHandshakeInterceptor interceptor = new WebSocketConfig.AuthenticatedHandshakeInterceptor();

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private boolean handshake(MockHttpServletResponse servletResponse) {
        ServerHttpRequest request = new ServletServerHttpRequest(new MockHttpServletRequest());
        ServerHttpResponse response = new ServletServerHttpResponse(servletResponse);
        return interceptor.beforeHandshake(request, response, mock(WebSocketHandler.class), new HashMap<>());
    }

    @Test
    void noAuthenticationIsRefused() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(handshake(response)).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void anAnonymousVisitorIsRefused() {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(handshake(response)).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void anAuthenticationThatIsNotAuthenticatedIsRefused() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("admin", "secret"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(handshake(response)).isFalse();
    }

    @Test
    void aSignedInUserIsAccepted() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("admin", "secret", "ROLE_ADMIN"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(handshake(response)).isTrue();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }
}
