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
package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: the URL policies' expressions on the application's requests read the
 * user the bridge resolved for Contexa alone, and a refusal of that user is the one of a signed-in user (403).
 */
@DisplayName("고객 경로의 URL 정책은 Contexa 신원으로 평가한다(R-10)")
class UrlPolicyEnforcementFilterContexaIdentityTest {

    private final CustomDynamicAuthorizationManager manager = mock(CustomDynamicAuthorizationManager.class);
    private final UrlPolicyEnforcementFilter filter = new UrlPolicyEnforcementFilter(manager, request -> true,
            new ObjectMapper());

    @BeforeEach
    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("정책 식은 bridge 신원을 받고, 거부는 로그인한 사용자의 403이다")
    @SuppressWarnings("unchecked")
    void thePoliciesReadTheBridgedUser() throws Exception {
        TestingAuthenticationToken carol = new TestingAuthenticationToken("carol", null, "ROLE_USER");
        carol.setAuthenticated(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader("Accept", "application/json");
        request.setAttribute(BridgeRequestAttributes.IDENTITY, carol);
        when(manager.checkNamedPolicies(any(), any(HttpServletRequest.class))).thenReturn(new AuthorizationDecision(false));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        ArgumentCaptor<Supplier<Authentication>> supplier = ArgumentCaptor.forClass(Supplier.class);
        verify(manager).checkNamedPolicies(supplier.capture(), eq(request));
        assertThat(supplier.getValue().get()).isSameAs(carol);
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
