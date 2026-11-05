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

import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.HostSignInEvents;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The application's failed sign-ins reach the decisions, and nothing else of Contexa. */
class HostOwnedSignInFailureListenerTest {

    private final InMemorySecurityContextDataStore store = spy(new InMemorySecurityContextDataStore());
    private final HostSignInEvents signInEvents = new HostSignInEvents();
    private final HostOwnedSignInFailureListener listener =
            new HostOwnedSignInFailureListener(() -> store, signInEvents);

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("three wrong passwords at the application's own manager are three failures of the name")
    void wrongPasswordsAreCounted() {
        failThreeTimes(publishingManager());

        assertThat(failuresOf("customer")).isEqualTo(3);
    }

    @Test
    @DisplayName("the sign-in after three wrong passwords tells the model of them, and so does a later call")
    void theSignInAfterWrongPasswordsTellsTheModel() {
        ProviderManager manager = publishingManager();
        failThreeTimes(manager);

        assertThat(promptOfASignInAt(manager)).contains("FailedLoginAttempts: 3");
    }

    @Test
    @DisplayName("a sign-in with no failure before it says zero: the application's events reach Contexa")
    void aFirstSignInSaysZero() {
        assertThat(promptOfASignInAt(publishingManager())).contains("FailedLoginAttempts: 0");
    }

    @Test
    @DisplayName("a manager built by hand publishes nothing: the count stays unknown, never zero")
    void aManagerThatPublishesNothingLeavesTheCountUnknown() {
        ProviderManager silent = silentManager();
        failThreeTimes(silent);

        assertThat(signInEvents.reaching()).isFalse();
        assertThat(promptOfASignInAt(silent)).contains("FailedLoginAttempts: UNKNOWN");
    }

    @Test
    @DisplayName("a name nobody has is counted as any other: the application does not say which it was")
    void aNameNobodyHasIsCounted() {
        assertThatThrownBy(() -> publishingManager().authenticate(attempt("nobody", "guess")))
                .isInstanceOf(AuthenticationException.class);

        assertThat(failuresOf("nobody")).isEqualTo(1);
    }

    @Test
    @DisplayName("the failure is kept under the name alone: the address's limit has nothing of it")
    void theAddressIsNotKept() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr("198.51.100.7");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        long now = System.currentTimeMillis();

        listener.onApplicationEvent(badCredentials(attempt("customer", "wrong")));

        assertThat(store.getRecentLoginFailureCount(null, "198.51.100.7", now - 60_000, now + 60_000)).isZero();
        verify(store).recordLoginFailure(eq("customer"), isNull(), anyLong());
    }

    @Test
    @DisplayName("one failure a request reports twice is one failure")
    void oneFailureOfARequestIsCountedOnce() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest("POST", "/login")));

        listener.onApplicationEvent(badCredentials(attempt("customer", "wrong")));
        listener.onApplicationEvent(badCredentials(attempt("customer", "wrong")));

        assertThat(failuresOf("customer")).isEqualTo(1);
    }

    @Test
    @DisplayName("the failure is kept on the request's clock, the one its window is read on")
    void aFailureIsKeptOnTheRequestsClock() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        Instant observedAt = Instant.parse("2026-09-30T03:14:00Z");
        RequestSecurityContextAttributes.write(request, RequestSecurityContextAttributes.Field.OBSERVED_AT,
                observedAt.toString(), true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        listener.onApplicationEvent(badCredentials(attempt("customer", "wrong")));

        assertThat(store.findRecentLoginFailures("customer", observedAt.toEpochMilli() - 1_000,
                observedAt.toEpochMilli() + 1_000)).isEqualTo(1);
    }

    @Test
    @DisplayName("a rejected bearer token is no sign-in, and its value is kept nowhere")
    void aRejectedBearerTokenIsNotKept() {
        listener.onApplicationEvent(badCredentials(new BearerTokenAuthenticationToken("the-token-value")));

        verify(store, never()).recordLoginFailure(any(), any(), anyLong());
        assertThat(signInEvents.reaching()).isFalse();
    }

    @Test
    @DisplayName("an OAuth2 client's failure is no person's sign-in")
    void aClientsFailureIsNotKept() {
        RegisteredClient client = RegisteredClient.withId("client-1").clientId("agent-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();

        listener.onApplicationEvent(badCredentials(new OAuth2ClientAuthenticationToken(client,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "wrong")));

        verify(store, never()).recordLoginFailure(any(), any(), anyLong());
    }

    @Test
    @DisplayName("a store that did not answer or a manager without a provider says nothing of the person who tried")
    void aFailureThatJudgedNoCredentialIsNotCounted() {
        Authentication attempt = attempt("customer", "right");

        listener.onApplicationEvent(new AuthenticationFailureServiceExceptionEvent(attempt,
                new AuthenticationServiceException("the application's database is down")));
        listener.onApplicationEvent(new AuthenticationFailureProviderNotFoundEvent(attempt,
                new ProviderNotFoundException("no provider")));

        assertThat(failuresOf("customer")).isZero();
        assertThat(signInEvents.reaching()).as("the events do reach Contexa").isTrue();
    }

    @Test
    @DisplayName("a name as long as a request can make it takes no memory")
    void aNameOfAMegabyteIsNotKept() {
        listener.onApplicationEvent(badCredentials(attempt("x".repeat(1_000_000), "wrong")));

        verify(store, never()).recordLoginFailure(notNull(), any(), anyLong());
    }

    @Test
    @DisplayName("the application's sign-in is the application's, whatever happens to the note of its failure")
    void nothingOfThisStopsTheApplicationsSignIn() {
        SecurityContextDataStore broken = mock(SecurityContextDataStore.class);
        doThrow(new IllegalStateException("store down")).when(broken).recordLoginFailure(any(), any(), anyLong());
        Authentication hostile = mock(Authentication.class);
        when(hostile.getName()).thenThrow(new IllegalStateException("a principal that fails"));

        assertThatCode(() -> {
            new HostOwnedSignInFailureListener(() -> broken, signInEvents).onApplicationEvent(
                    badCredentials(attempt("customer", "wrong")));
            new HostOwnedSignInFailureListener(() -> null, signInEvents).onApplicationEvent(
                    badCredentials(attempt("customer", "wrong")));
            listener.onApplicationEvent(badCredentials(hostile));
        }).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a sign-in event of the filter proves nothing of the manager: it is not the manager's")
    void theFiltersSignInEventProvesNothing() {
        listener.onApplicationEvent(new InteractiveAuthenticationSuccessEvent(attempt("customer", "right"),
                UsernamePasswordAuthenticationFilter.class));

        assertThat(signInEvents.reaching()).isFalse();
    }

    private int failuresOf(String name) {
        long now = System.currentTimeMillis();
        Integer failures = store.findRecentLoginFailures(name, now - 60_000, now + 60_000);
        assertThat(failures).isNotNull();
        return failures;
    }

    private void failThreeTimes(ProviderManager manager) {
        for (int attempt = 0; attempt < 3; attempt++) {
            assertThatThrownBy(() -> manager.authenticate(attempt("customer", "wrong")))
                    .isInstanceOf(BadCredentialsException.class);
        }
    }

    /** The sign-in as a filter makes it: the manager, then the context, then the event of the sign-in. */
    private String promptOfASignInAt(ProviderManager manager) {
        List<ZeroTrustSpringEvent> events = new ArrayList<>();
        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(event -> events.add((ZeroTrustSpringEvent) event),
                new TieredStrategyProperties(), store, new SecurityPlaneProperties());
        ReflectionTestUtils.setField(publisher, "hostSignInEvents", signInEvents);
        Authentication signedIn = manager.authenticate(attempt("customer", "right"));
        SecurityContextHolder.getContext().setAuthentication(signedIn);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest("POST", "/login")));

        new HostOwnedSignInListener(publisher).onApplicationEvent(new InteractiveAuthenticationSuccessEvent(signedIn,
                UsernamePasswordAuthenticationFilter.class));

        return new PromptContextComposer().composeAuthenticationAndAssuranceSection(
                new DefaultCanonicalSecurityContextProvider(new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator())
                        .resolve(ZeroTrustSecurityEventConverter.convert(events.get(0))).orElseThrow());
    }

    private ProviderManager publishingManager() {
        ProviderManager manager = silentManager();
        manager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher(
                event -> listener.onApplicationEvent((AbstractAuthenticationEvent) event)));
        return manager;
    }

    private static ProviderManager silentManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(new InMemoryUserDetailsManager(
                User.withUsername("customer").password("{noop}right")
                        .authorities(AuthorityUtils.createAuthorityList("ROLE_USER")).build()));
        return new ProviderManager(provider);
    }

    private static Authentication attempt(String name, String password) {
        return UsernamePasswordAuthenticationToken.unauthenticated(name, password);
    }

    private static AuthenticationFailureBadCredentialsEvent badCredentials(Authentication attempt) {
        return new AuthenticationFailureBadCredentialsEvent(attempt, new BadCredentialsException("wrong"));
    }
}
