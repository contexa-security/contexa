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
package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The user store the REST sign-in reads: Contexa's own where Contexa owns the sign-in, the application's where it keeps it. */
class RestSignInStoreTest {

    private final UserDetailsService applicationStore = new InMemoryUserDetailsManager(
            User.withUsername("alice").password("alice-password").roles("USER").build());
    private final UserDetailsService contexaStore = new InMemoryUserDetailsManager(
            User.withUsername("administrator").password("administrator-password").roles("ADMIN").build());

    @Test
    void whereContexaOwnsTheSignInTheAdministratorSignsInAndTheApplicationsUserIsRefused() {
        AuthenticationProvider restSignIn = restSignIn(true);

        assertThat(restSignIn.authenticate(RestAuthenticationToken.unauthenticated("administrator", "administrator-password"))
                .isAuthenticated()).isTrue();
        assertThatThrownBy(() -> restSignIn.authenticate(RestAuthenticationToken.unauthenticated("alice", "alice-password")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void whereTheApplicationKeepsItsSignInTheApplicationsStoreIsRead() {
        AuthenticationProvider restSignIn = restSignIn(false);

        assertThat(restSignIn.authenticate(RestAuthenticationToken.unauthenticated("alice", "alice-password"))
                .isAuthenticated()).isTrue();
        assertThatThrownBy(() -> restSignIn.authenticate(
                RestAuthenticationToken.unauthenticated("administrator", "administrator-password")))
                .isInstanceOf(BadCredentialsException.class);
    }

    /** The provider the REST configurer gives its chain, beside the one store of the application's. */
    @SuppressWarnings("unchecked")
    private AuthenticationProvider restSignIn(boolean contexaOwnsTheSignIn) {
        ApplicationContext context = mock(ApplicationContext.class);
        ObjectProvider<UserDetailsService> stores = mock(ObjectProvider.class);
        when(stores.getIfUnique()).thenReturn(applicationStore);
        when(context.getBeanProvider(UserDetailsService.class)).thenReturn(stores);
        if (contexaOwnsTheSignIn) {
            when(context.containsBean(ContexaUserStore.BEAN_NAME)).thenReturn(true);
            when(context.getBean(ContexaUserStore.BEAN_NAME, UserDetailsService.class)).thenReturn(contexaStore);
        }
        when(context.getBean(PasswordEncoder.class)).thenReturn(NoOpPasswordEncoder.getInstance());
        when(context.getBean(LoginPolicyHandler.class)).thenThrow(new NoSuchBeanDefinitionException(LoginPolicyHandler.class));
        HttpSecurity http = mock(HttpSecurity.class);

        new RestAuthenticationConfigurer<HttpSecurity>().beforeFilterCreation(http, mock(AuthenticationManager.class), context);

        ArgumentCaptor<AuthenticationProvider> provider = ArgumentCaptor.forClass(AuthenticationProvider.class);
        verify(http).authenticationProvider(provider.capture());
        return provider.getValue();
    }
}
