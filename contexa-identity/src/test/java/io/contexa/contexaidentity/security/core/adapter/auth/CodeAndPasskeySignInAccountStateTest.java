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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationProvider;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationRequestToken;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import java.time.Instant;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A sign-in by code or by passkey answers to the account as the password does: a locked or disabled account does not sign
 * in, alone or as a step of the MFA flow, whatever the code or the key proves.
 */
class CodeAndPasskeySignInAccountStateTest {

    private final HttpSecurity http = mock(HttpSecurity.class);
    private final ApplicationContext context = mock(ApplicationContext.class);
    private final EmailOneTimeTokenService codes = mock(EmailOneTimeTokenService.class);
    /** The user each passkey assertion of a test is the key of. */
    private final Map<RelyingPartyAuthenticationRequest, PublicKeyCredentialUserEntity> names = new IdentityHashMap<>();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        UserDetailsService accounts = new InMemoryUserDetailsManager(
                User.withUsername("open").password("{noop}x").roles("USER").build(),
                User.withUsername("locked").password("{noop}x").roles("USER").accountLocked(true).build(),
                User.withUsername("disabled").password("{noop}x").roles("USER").disabled(true).build());
        ObjectProvider<UserDetailsService> store = mock(ObjectProvider.class);
        when(store.getIfUnique()).thenReturn(accounts);
        when(context.getBeanProvider(UserDetailsService.class)).thenReturn(store);
        PlatformContext platform = mock(PlatformContext.class);
        when(platform.applicationContext()).thenReturn(context);
        when(http.getSharedObject(PlatformContext.class)).thenReturn(platform);
        when(context.getBean(ContexaOneTimeTokens.BEAN_NAME, ContexaOneTimeTokens.class))
                .thenReturn(new ContexaOneTimeTokens(codes));
        when(context.getBean(AuthUrlProvider.class)).thenReturn(mock(AuthUrlProvider.class));
        when(context.getBean(AuthResponseWriter.class)).thenReturn(mock(AuthResponseWriter.class));
    }

    @Test
    void aLockedAccountDoesNotSignInByCodeAlone() throws Exception {
        AuthenticationProvider codeSignIn = codeSignIn(new OttAuthenticationAdapter());

        assertThatThrownBy(() -> codeSignIn.authenticate(codeOf("locked"))).isInstanceOf(LockedException.class);
    }

    @Test
    void aDisabledAccountDoesNotSignInByCodeAlone() throws Exception {
        AuthenticationProvider codeSignIn = codeSignIn(new OttAuthenticationAdapter());

        assertThatThrownBy(() -> codeSignIn.authenticate(codeOf("disabled"))).isInstanceOf(DisabledException.class);
    }

    @Test
    void aLockedAccountDoesNotPassTheCodeStepOfTheMfaFlow() throws Exception {
        AuthenticationProvider codeStep = codeSignIn(new MfaOttAuthenticationAdapter());

        assertThatThrownBy(() -> codeStep.authenticate(codeOf("locked"))).isInstanceOf(LockedException.class);
        assertThatThrownBy(() -> codeStep.authenticate(codeOf("disabled"))).isInstanceOf(DisabledException.class);
    }

    @Test
    void anOpenAccountSignsInByCode() throws Exception {
        AuthenticationProvider codeSignIn = codeSignIn(new OttAuthenticationAdapter());

        Authentication signedIn = codeSignIn.authenticate(codeOf("open"));

        assertThat(signedIn.isAuthenticated()).isTrue();
        assertThat(signedIn.getName()).isEqualTo("open");
    }

    @Test
    void aLockedOrDisabledAccountDoesNotSignInWithAPasskey() throws Exception {
        AuthenticationProvider passkeySignIn = passkeySignIn(new PasskeyAuthenticationAdapter());

        assertThatThrownBy(() -> passkeySignIn.authenticate(passkeyOf("locked")))
                .isInstanceOf(BadCredentialsException.class).hasCauseInstanceOf(LockedException.class);
        assertThatThrownBy(() -> passkeySignIn.authenticate(passkeyOf("disabled")))
                .isInstanceOf(BadCredentialsException.class).hasCauseInstanceOf(DisabledException.class);
        assertThat(passkeySignIn.authenticate(passkeyOf("open")).isAuthenticated()).isTrue();
    }

    @Test
    void aLockedAccountDoesNotPassThePasskeyStepOfTheMfaFlow() throws Exception {
        AuthenticationProvider passkeyStep = passkeySignIn(new MfaPasskeyAuthenticationAdapter());

        assertThatThrownBy(() -> passkeyStep.authenticate(passkeyOf("locked")))
                .isInstanceOf(BadCredentialsException.class).hasCauseInstanceOf(LockedException.class);
    }

    /** Where Contexa owns the sign-in, a code signs Contexa's account in and the application's one store is not asked. */
    @Test
    void whereContexaOwnsTheSignInACodeSignsContexasAccountInAndNotTheApplicationsUser() throws Exception {
        contexaOwnsTheSignIn();

        AuthenticationProvider codeSignIn = codeSignIn(new OttAuthenticationAdapter());

        assertThat(codeSignIn.authenticate(codeOf("administrator")).getName()).isEqualTo("administrator");
        assertThatThrownBy(() -> codeSignIn.authenticate(codeOf("open"))).isInstanceOf(AuthenticationException.class);
        verify(context.getBeanProvider(UserDetailsService.class), never()).getIfUnique();
    }

    /** Where Contexa owns the sign-in, a passkey signs Contexa's account in and the application's one store is not asked. */
    @Test
    void whereContexaOwnsTheSignInAPasskeySignsContexasAccountInAndNotTheApplicationsUser() throws Exception {
        contexaOwnsTheSignIn();

        AuthenticationProvider passkeySignIn = passkeySignIn(new PasskeyAuthenticationAdapter());

        assertThat(passkeySignIn.authenticate(passkeyOf("administrator")).getName()).isEqualTo("administrator");
        assertThatThrownBy(() -> passkeySignIn.authenticate(passkeyOf("open"))).isInstanceOf(AuthenticationException.class);
        verify(context.getBeanProvider(UserDetailsService.class), never()).getIfUnique();
    }

    /** The application has one store (set up above) and Contexa owns the sign-in: its store exists, with its own administrator. */
    private void contexaOwnsTheSignIn() {
        UserDetailsService contexaAccounts = new InMemoryUserDetailsManager(
                User.withUsername("administrator").password("{noop}x").roles("ADMIN").build());
        when(context.containsBean(ContexaUserStore.BEAN_NAME)).thenReturn(true);
        when(context.getBean(ContexaUserStore.BEAN_NAME, UserDetailsService.class)).thenReturn(contexaAccounts);
    }

    /** The provider the adapter gives Spring's one-time token login, which reads the code of the user named by "user". */
    @SuppressWarnings("unchecked")
    private AuthenticationProvider codeSignIn(BaseOttAuthenticationAdapter adapter) throws Exception {
        when(codes.consume(any())).thenAnswer(invocation -> {
            OneTimeTokenAuthenticationToken presented = invocation.getArgument(0);
            return new DefaultOneTimeToken(presented.getTokenValue(), presented.getTokenValue(),
                    Instant.now().plusSeconds(60));
        });
        OneTimeTokenLoginConfigurer<HttpSecurity> configurer = mock(OneTimeTokenLoginConfigurer.class);
        when(configurer.defaultSubmitPageUrl(any())).thenReturn(configurer);
        when(configurer.loginProcessingUrl(any())).thenReturn(configurer);
        when(configurer.showDefaultSubmitPage(any(Boolean.class))).thenReturn(configurer);
        when(configurer.tokenGeneratingUrl(any())).thenReturn(configurer);
        when(configurer.tokenService(any())).thenReturn(configurer);
        when(configurer.tokenGenerationSuccessHandler(any())).thenReturn(configurer);
        when(configurer.generateRequestResolver(any())).thenReturn(configurer);
        when(configurer.authenticationProvider(any())).thenReturn(configurer);
        when(http.oneTimeTokenLogin(any(Customizer.class))).thenAnswer(invocation -> {
            Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
            customizer.customize(configurer);
            return http;
        });
        OttOptions options = mock(OttOptions.class);
        when(options.getLoginProcessingUrl()).thenReturn("/login/ott");

        adapter.configureHttpSecurityForOtt(http, options, mock(OneTimeTokenGenerationSuccessHandler.class),
                mock(PlatformAuthenticationSuccessHandler.class), mock(PlatformAuthenticationFailureHandler.class));

        ArgumentCaptor<AuthenticationProvider> provider = ArgumentCaptor.forClass(AuthenticationProvider.class);
        verify(configurer).authenticationProvider(provider.capture());
        return provider.getValue();
    }

    /** Spring's passkey provider as the WebAuthn configurer builds it, with the store the adapter shares with it. */
    @SuppressWarnings("unchecked")
    private AuthenticationProvider passkeySignIn(BasePasskeyAuthenticationAdapter adapter) throws Exception {
        WebAuthnConfigurer<HttpSecurity> configurer = mock(WebAuthnConfigurer.class);
        when(configurer.rpName(any())).thenReturn(configurer);
        when(configurer.rpId(any())).thenReturn(configurer);
        when(configurer.allowedOrigins(any(Set.class))).thenReturn(configurer);
        when(http.webAuthn(any(Customizer.class))).thenAnswer(invocation -> {
            Customizer<WebAuthnConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
            customizer.customize(configurer);
            return http;
        });
        PasskeyOptions options = mock(PasskeyOptions.class);
        when(options.getRpName()).thenReturn("Contexa");
        when(options.getRpId()).thenReturn("localhost");
        when(options.getAllowedOrigins()).thenReturn(Set.of("http://localhost"));

        adapter.configureHttpSecurity(http, options, null, null, null);

        ArgumentCaptor<UserDetailsService> shared = ArgumentCaptor.forClass(UserDetailsService.class);
        verify(http).setSharedObject(eq(UserDetailsService.class), shared.capture());
        WebAuthnRelyingPartyOperations relyingParty = mock(WebAuthnRelyingPartyOperations.class);
        when(relyingParty.authenticate(any())).thenAnswer(invocation -> names.get(invocation.getArgument(0)));
        return new WebAuthnAuthenticationProvider(relyingParty, shared.getValue());
    }

    /** A code whose value names the user it was issued to (the code service above hands it back so). */
    private static OneTimeTokenAuthenticationToken codeOf(String username) {
        return OneTimeTokenAuthenticationToken.unauthenticated(username);
    }

    /** An assertion the relying party verifies as the passkey of the user. */
    private WebAuthnAuthenticationRequestToken passkeyOf(String username) {
        RelyingPartyAuthenticationRequest request = mock(RelyingPartyAuthenticationRequest.class);
        PublicKeyCredentialUserEntity user = mock(PublicKeyCredentialUserEntity.class);
        when(user.getName()).thenReturn(username);
        names.put(request, user);
        return new WebAuthnAuthenticationRequestToken(request);
    }
}
