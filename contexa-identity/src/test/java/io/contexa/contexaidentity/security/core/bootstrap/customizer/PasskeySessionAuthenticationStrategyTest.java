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
package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A passkey sign-in reaches the session strategy of its chain under the person's entry of the user store: the registry
 * of sessions counts sessions per principal, and the passkey's own principal is another object at every sign-in.
 */
class PasskeySessionAuthenticationStrategyTest {

    private final SessionAuthenticationStrategy strategyOfChain = mock(SessionAuthenticationStrategy.class);
    private final UserDetailsService users = mock(UserDetailsService.class);
    private final PasskeySessionAuthenticationStrategy strategy = new PasskeySessionAuthenticationStrategy(strategyOfChain, users);
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    /** The shape of Spring Security's passkey sign-in: a principal that is no entry of the user store, and a name. */
    private static Authentication passkeySignIn(String username) {
        Object passkeyUser = new Object();
        return new TestingAuthenticationToken(passkeyUser, null, AuthorityUtils.createAuthorityList("ROLE_USER")) {
            @Override
            public String getName() {
                return username;
            }
        };
    }

    private Authentication given() {
        ArgumentCaptor<Authentication> given = ArgumentCaptor.forClass(Authentication.class);
        verify(strategyOfChain).onAuthentication(given.capture(), same(request), same(response));
        return given.getValue();
    }

    @Test
    void twoPasskeySignInsOfOnePersonReachTheStrategyUnderOnePrincipal() {
        UserDetails person = User.withUsername("user").password("n/a").roles("USER").build();
        when(users.loadUserByUsername("user")).thenReturn(person);
        Authentication signIn = passkeySignIn("user");

        strategy.onAuthentication(signIn, request, response);

        Authentication given = given();
        assertThat(given.getPrincipal()).isSameAs(person);
        assertThat(given.getName()).isEqualTo("user");
        assertThat(given.isAuthenticated()).isTrue();
        assertThat(AuthorityUtils.authorityListToSet(given.getAuthorities())).containsExactly("ROLE_USER");
    }

    @Test
    void aSignInThatAlreadyCarriesAnEntryOfTheUserStoreIsGivenAsItIs() {
        UserDetails person = User.withUsername("user").password("n/a").roles("USER").build();
        Authentication signIn = UsernamePasswordAuthenticationToken.authenticated(person, null, person.getAuthorities());

        strategy.onAuthentication(signIn, request, response);

        assertThat(given()).isSameAs(signIn);
        verify(users, never()).loadUserByUsername("user");
    }

    @Test
    void aStoreThatDoesNotGiveThePersonLeavesTheSignInAsItIs() {
        when(users.loadUserByUsername("user")).thenThrow(new UsernameNotFoundException("user"));
        Authentication signIn = passkeySignIn("user");

        strategy.onAuthentication(signIn, request, response);

        assertThat(given()).isSameAs(signIn);
    }
}
