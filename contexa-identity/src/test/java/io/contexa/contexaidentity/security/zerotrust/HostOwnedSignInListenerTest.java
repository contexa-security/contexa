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

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** Ownership design S-8 (D-4): the application's interactive sign-in goes to the engine as Contexa's own does. */
class HostOwnedSignInListenerTest {

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("an interactive sign-in of the application is published as an authentication success")
    void interactiveSignInIsPublished() {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.addHeader("User-Agent", "browser/1.0");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        TestingAuthenticationToken signedIn = new TestingAuthenticationToken("customer", null, "ROLE_USER");

        new HostOwnedSignInListener(publisher).onApplicationEvent(new InteractiveAuthenticationSuccessEvent(
                signedIn, UsernamePasswordAuthenticationFilter.class));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> payload = ArgumentCaptor.forClass(Map.class);
        verify(publisher).publishAuthenticationSuccess(eq(signedIn), eq(request), payload.capture());
        assertThat(payload.getValue()).containsEntry("authenticationType", "HOST_SIGN_IN")
                .containsEntry("signedInBy", "UsernamePasswordAuthenticationFilter");
    }

    @Test
    @DisplayName("a sign-in that cannot be sent is the application's sign-in all the same")
    void aSignInThatCannotBeSentStaysTheApplications() {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        doThrow(new IllegalStateException("no engine")).when(publisher).publishAuthenticationSuccess(any(), any(), any());

        assertThatCode(() -> new HostOwnedSignInListener(publisher).onApplicationEvent(
                new InteractiveAuthenticationSuccessEvent(new TestingAuthenticationToken("customer", null, "ROLE_USER"),
                        UsernamePasswordAuthenticationFilter.class)))
                .doesNotThrowAnyException();
    }
}
