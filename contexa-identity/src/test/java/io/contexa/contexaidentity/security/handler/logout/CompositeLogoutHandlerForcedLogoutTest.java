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

import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** What a change of an account relies on: one store that fails ends what the other stores can still end. */
class CompositeLogoutHandlerForcedLogoutTest {

    private final ZeroTrustSecurityService sessions = mock(ZeroTrustSecurityService.class);
    private final DeviceAwareOAuth2AuthorizationService tokens = mock(DeviceAwareOAuth2AuthorizationService.class);
    private final CompositeLogoutHandler handler = new CompositeLogoutHandler(List.of(mock(LogoutStrategy.class)),
            mock(TokenService.class), sessions, tokens);

    @Test
    @DisplayName("a forced logout ends the sessions and the tokens of the user")
    void itEndsTheSessionsAndTheTokens() {
        handler.forceLogoutByUserId("alice", "PASSWORD_CHANGED");

        verify(sessions).invalidateAllUserSessions("alice", "PASSWORD_CHANGED");
        verify(tokens).invalidateAllByPrincipalName("alice");
    }

    @Test
    @DisplayName("sessions that cannot be ended leave the tokens to be ended, and reach nobody as an error")
    void aStoreOfSessionsThatFails() {
        doThrow(new IllegalStateException("store down")).when(sessions).invalidateAllUserSessions(anyString(), any());
        doThrow(new IllegalStateException("store down")).when(sessions).cleanupOnLogout(anyString(), any());

        assertThatCode(() -> handler.forceLogoutByUserId("alice", "PASSWORD_CHANGED")).doesNotThrowAnyException();

        verify(tokens).invalidateAllByPrincipalName("alice");
    }

    @Test
    @DisplayName("tokens that cannot be ended reach nobody as an error")
    void aStoreOfTokensThatFails() {
        doThrow(new IllegalStateException("database down")).when(tokens).invalidateAllByPrincipalName(anyString());

        assertThatCode(() -> handler.forceLogoutByUserId("alice", "PASSWORD_CHANGED")).doesNotThrowAnyException();
    }
}
