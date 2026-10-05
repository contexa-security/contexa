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
package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class OAuth2LogoutSuccessHandlerTest {

    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);

    @Test
    @DisplayName("A plain browser logout is sent to the sign-in page of the flow")
    void browserLogoutRedirects() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        request.setContextPath("/app");
        request.addHeader("Accept", "text/html");
        MockHttpServletResponse response = new MockHttpServletResponse();

        new OAuth2LogoutSuccessHandler(responseWriter).withLogoutSuccessUrl("/mfa/login")
                .onLogoutSuccess(request, response, null);

        assertThat(response.getRedirectedUrl()).isEqualTo("/app/mfa/login");
        verify(responseWriter, never()).writeSuccessResponse(any(), any(), anyInt());
    }

    @Test
    @DisplayName("An API logout keeps the JSON response")
    void apiLogoutWritesJson() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        new OAuth2LogoutSuccessHandler(responseWriter).withLogoutSuccessUrl("/mfa/login")
                .onLogoutSuccess(request, response, null);

        assertThat(response.getRedirectedUrl()).isNull();
        verify(responseWriter).writeSuccessResponse(eq(response), eq(Map.of("status", "LOGGED_OUT")), eq(200));
    }

    @Test
    @DisplayName("Without a sign-in page every logout gets the JSON response")
    void noUrlWritesJson() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        request.addHeader("Accept", "text/html");
        MockHttpServletResponse response = new MockHttpServletResponse();

        new OAuth2LogoutSuccessHandler(responseWriter).onLogoutSuccess(request, response, null);

        verify(responseWriter).writeSuccessResponse(eq(response), eq(Map.of("status", "LOGGED_OUT")), eq(200));
    }
}
