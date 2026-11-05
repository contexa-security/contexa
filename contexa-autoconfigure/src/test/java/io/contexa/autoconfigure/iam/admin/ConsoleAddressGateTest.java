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

import io.contexa.contexacommon.security.LoginAddressBlockedException;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** PR-69: the console signs its administrators in on a chain of its own, through a provider that is not Contexa's. */
class ConsoleAddressGateTest {

    private final LoginPolicyHandler handler = mock(LoginPolicyHandler.class);
    private final AuthenticationProvider credentials = mock(AuthenticationProvider.class);
    private final Authentication attempt = new UsernamePasswordAuthenticationToken("admin", "secret");

    private ProviderManager manager(LoginPolicyHandler... handlers) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        for (LoginPolicyHandler each : handlers) {
            beans.addBean("handler", each);
        }
        when(credentials.supports(any())).thenReturn(true);
        return new ProviderManager(new ConsoleAddressGate(beans.getBeanProvider(LoginPolicyHandler.class)), credentials);
    }

    @Test
    @DisplayName("a blocked address stops at the gate: the provider of the credentials is never asked")
    void aBlockedAddressStopsAtTheGate() {
        doThrow(new LoginAddressBlockedException("blocked")).when(handler).checkSignInAddress("admin");

        assertThatThrownBy(() -> manager(handler).authenticate(attempt)).isInstanceOf(LoginAddressBlockedException.class);
        verify(credentials, never()).authenticate(any());
    }

    @Test
    @DisplayName("any other address goes on to the provider of the credentials")
    void anyOtherAddressGoesOn() {
        Authentication signedIn = UsernamePasswordAuthenticationToken.authenticated(
                "admin", null, AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
        when(credentials.authenticate(attempt)).thenReturn(signedIn);

        assertThat(manager(handler).authenticate(attempt)).isSameAs(signedIn);
    }

    @Test
    @DisplayName("without a login policy the credentials decide")
    void withoutAPolicy() {
        Authentication signedIn = UsernamePasswordAuthenticationToken.authenticated(
                "admin", null, AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
        when(credentials.authenticate(attempt)).thenReturn(signedIn);

        assertThat(manager().authenticate(attempt)).isSameAs(signedIn);
    }
}
