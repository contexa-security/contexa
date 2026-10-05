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
package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class LoginAttemptEventListenerTest {

    private final LoginPolicyHandler handler = mock(LoginPolicyHandler.class);
    private final LoginAttemptEventListener listener = new LoginAttemptEventListener(handler);

    @Test
    @DisplayName("A rejected bearer token is not recorded as a failed login")
    void rejectedBearerTokenIsNotALoginFailure() {
        BearerTokenAuthenticationToken presented = new BearerTokenAuthenticationToken("eyJhbGciOiJSUzI1NiJ9.e30.sig");

        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(
                presented, new InvalidBearerTokenException("The access-token authorization is not active")));

        verify(handler, never()).onLoginFailure(any(), any(), any(), any());
        verify(handler, never()).onLoginFailure(any());
    }

    @Test
    @DisplayName("A request authenticated with a bearer token is not recorded as a successful login")
    void acceptedBearerTokenIsNotALoginSuccess() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("admin")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        listener.onSuccess(new AuthenticationSuccessEvent(new JwtAuthenticationToken(jwt, List.of())));

        verify(handler, never()).onLoginSuccess(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("An OAuth2 client authenticated by the authorization server is not recorded as a login")
    void clientAuthenticationIsNotALogin() {
        RegisteredClient client = RegisteredClient.withId("internal-client-id")
                .clientId("default-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        listener.onSuccess(new AuthenticationSuccessEvent(
                new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret")));

        verify(handler, never()).onLoginSuccess(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("A failed password login is still recorded")
    void failedPasswordLoginIsRecorded() {
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(
                UsernamePasswordAuthenticationToken.unauthenticated("admin", "wrong"),
                new BadCredentialsException("Bad credentials")));

        verify(handler).onLoginFailure(eq("admin"), any(), eq("BadCredentialsException"), eq("EVENT"));
    }
}
