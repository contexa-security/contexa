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
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.service.ott.OneTimeTokenAddressRefusedException;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** PR-19: a code request that named another address than the registered one answered 500 and ended the MFA flow. */
class OneTimeTokenAddressRefusalFilterTest {

    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final OneTimeTokenAddressRefusalFilter filter =
            new OneTimeTokenAddressRefusalFilter(responseWriter, "/mfa/ott/request-code-ui");
    private final FilterChain refused = (request, response) -> {
        throw new OneTimeTokenAddressRefusedException("Invalid one-time token delivery request");
    };

    private MockHttpServletRequest codeRequest() {
        return new MockHttpServletRequest("POST", "/mfa/ott/generate-code");
    }

    @Test
    @DisplayName("a browser goes back to the page that asks for the code, and says why")
    void aBrowserGoesBackToThePage() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(codeRequest(), response, refused);

        assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/ott/request-code-ui?error=address_mismatch");
        verifyNoInteractions(responseWriter);
    }

    @Test
    @DisplayName("the context path and the page of a flow with a URL prefix are kept")
    void theContextPathAndTheFlowsPage() throws Exception {
        filter.setRequestPage("/agent/mfa/ott/request-code-ui");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/app/agent/mfa/ott/generate-code");
        request.setContextPath("/app");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, refused);

        assertThat(response.getRedirectedUrl()).isEqualTo("/app/agent/mfa/ott/request-code-ui?error=address_mismatch");
    }

    @Test
    @DisplayName("an API client gets 400 with the code of the refusal, not a server error")
    void anApiClientGetsTheCode() throws Exception {
        MockHttpServletRequest request = codeRequest();
        request.addHeader("Accept", "application/json");

        filter.doFilter(request, new MockHttpServletResponse(), refused);

        verify(responseWriter).writeErrorResponse(any(), eq(400), eq(OneTimeTokenAddressRefusalFilter.ERROR_CODE), anyString(),
                eq("/mfa/ott/generate-code"), any());
    }

    @Test
    @DisplayName("any other failure stays what it is")
    void anyOtherFailureGoesOn() {
        FilterChain failing = (request, response) -> {
            throw new IllegalStateException("Email sender is not configured");
        };

        assertThatThrownBy(() -> filter.doFilter(codeRequest(), new MockHttpServletResponse(), failing))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("a request nothing refuses goes on untouched")
    void anythingElseGoesOn() throws ServletException, IOException {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(codeRequest(), response, (request, answer) -> {
        });

        assertThat(response.getRedirectedUrl()).isNull();
        verifyNoInteractions(responseWriter);
    }
}
