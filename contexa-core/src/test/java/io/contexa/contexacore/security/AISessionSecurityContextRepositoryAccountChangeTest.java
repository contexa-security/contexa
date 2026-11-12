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
package io.contexa.contexacore.security;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import io.contexa.contexacore.security.session.InMemorySessionIdResolver;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Q-14 (PR-35, PR-43): what an administrator changes reaches the sessions that are open. */
class AISessionSecurityContextRepositoryAccountChangeTest {

    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    private final SecuritySessionProperties sessionProperties = new SecuritySessionProperties();
    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), properties, actions, new InMemoryBlockingSignalBroadcaster());
    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
    private final UserDetailsService accounts = mock(UserDetailsService.class);
    private final AISessionSecurityContextRepository repository = new AISessionSecurityContextRepository(
            new AISecurityContextSupport(properties, service, new InMemorySessionIdResolver(sessionProperties)), store, null);
    private final String user = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        properties.setEnabled(true);
        repository.setAccountRefresher(new SessionAccountRefresher(store, accounts));
    }

    private static UnifiedCustomUserDetails account(String name, boolean enabled, boolean externalAuthOnly,
                                                    String... authorities) {
        Set<GrantedAuthority> granted = Arrays.stream(authorities).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        return new UnifiedCustomUserDetails(UserDto.builder().id(1L).username(name).password("{noop}x").enabled(enabled)
                .externalAuthOnly(externalAuthOnly).build(), granted);
    }

    private MockHttpServletRequest signedInSession(String... authorities) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        UnifiedCustomUserDetails details = account(user, true, false, authorities);
        SecurityContext context = new SecurityContextImpl(
                UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities()));
        request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", context);
        repository.saveContext(context, request, new MockHttpServletResponse());
        return request;
    }

    private List<String> authoritiesOf(MockHttpServletRequest request) {
        return repository.loadDeferredContext(request).get().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
    }

    private MockHttpServletRequest nextRequest(MockHttpServletRequest previous) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(previous.getSession(false));
        return request;
    }

    @Test
    @DisplayName("nothing changed: a session reads no account")
    void nothingChanged() {
        MockHttpServletRequest request = signedInSession("ROLE_KEEPER");

        assertThat(authoritiesOf(nextRequest(request))).contains("ROLE_KEEPER");

        verify(accounts, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("a right taken away is gone on the next request of the open session, and it reads the account once")
    void aRightTakenAway() {
        MockHttpServletRequest request = signedInSession("ROLE_USER", "ROLE_KEEPER");
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, true, false, "ROLE_USER"));

        store.advanceAuthoritiesVersion();

        assertThat(authoritiesOf(nextRequest(request))).contains("ROLE_USER").doesNotContain("ROLE_KEEPER");
        assertThat(authoritiesOf(nextRequest(request))).doesNotContain("ROLE_KEEPER");
        verify(accounts, times(1)).loadUserByUsername(user);
    }

    /** A sign-in that ends with the mail code: what the session really holds after MFA, as measured (Q-14). */
    private MockHttpServletRequest signedInWithACode(Object details, String... authorities) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        UnifiedCustomUserDetails account = account(user, true, false, authorities);
        OneTimeTokenAuthenticationToken authentication =
                new OneTimeTokenAuthenticationToken(account, account.getAuthorities());
        authentication.setDetails(details);
        SecurityContext context = new SecurityContextImpl(authentication);
        request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", context);
        repository.saveContext(context, request, new MockHttpServletResponse());
        return request;
    }

    @Test
    @DisplayName("a session signed in with a mail code follows the change, and keeps the facts of its login")
    void aSessionOfAMailCode() {
        Object loginFacts = "the facts of the login";
        MockHttpServletRequest request = signedInWithACode(loginFacts, "ROLE_USER");
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, true, false, "ROLE_USER", "ROLE_READER"));

        store.advanceAuthoritiesVersion();

        Authentication refreshed = repository.loadDeferredContext(nextRequest(request)).get().getAuthentication();
        assertThat(refreshed.getAuthorities()).extracting("authority").contains("ROLE_READER");
        assertThat(refreshed.getDetails()).isSameAs(loginFacts);
        assertThat(refreshed.getName()).isEqualTo(user);
    }

    @Test
    @DisplayName("a session signed in with a mail code ends with its account")
    void aDisabledAccountOfAMailCode() {
        MockHttpServletRequest request = signedInWithACode(null, "ROLE_USER");
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, false, false, "ROLE_USER"));

        store.advanceAuthoritiesVersion();

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("the forced logout reaches a session the repository saw: it is tracked on its first request")
    void aForcedLogoutReachesAnOpenSession() {
        MockHttpServletRequest request = signedInWithACode(null, "ROLE_USER");
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        repository.loadDeferredContext(nextRequest(request)).get();

        service.invalidateAllUserSessions(user, "ACCOUNT_DISABLED");

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
    }

    private static UnifiedCustomUserDetails signedInWithPassword(Long id, String name, LocalDateTime changedAt) {
        return new UnifiedCustomUserDetails(UserDto.builder().id(id).username(name).password("{noop}x").enabled(true)
                .passwordChangedAt(changedAt).build(), Set.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private MockHttpServletRequest sessionOf(UnifiedCustomUserDetails details) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        SecurityContext context = new SecurityContextImpl(
                UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities()));
        request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", context);
        repository.saveContext(context, request, new MockHttpServletResponse());
        return request;
    }

    @Test
    @DisplayName("a password changed after the sign-in ends a session the forced logout never knew")
    void aNewPasswordEndsTheSession() {
        LocalDateTime signedInWith = LocalDateTime.of(2026, 11, 1, 9, 0);
        MockHttpServletRequest request = sessionOf(signedInWithPassword(1L, user, signedInWith));
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        when(accounts.loadUserByUsername(user)).thenReturn(signedInWithPassword(1L, user, signedInWith.plusDays(1)));

        store.advanceAuthoritiesVersion();

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    @DisplayName("the first password of an account without a date ends the session as well")
    void theFirstNewPasswordEndsTheSession() {
        MockHttpServletRequest request = sessionOf(signedInWithPassword(1L, user, null));
        when(accounts.loadUserByUsername(user)).thenReturn(signedInWithPassword(1L, user, LocalDateTime.of(2026, 11, 2, 9, 0)));

        store.advanceAuthoritiesVersion();

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("a change of another account leaves a session with its password alone")
    void thePasswordItSignedInWithGoesOn() {
        LocalDateTime signedInWith = LocalDateTime.of(2026, 11, 1, 9, 0);
        MockHttpServletRequest request = sessionOf(signedInWithPassword(1L, user, signedInWith));
        when(accounts.loadUserByUsername(user)).thenReturn(signedInWithPassword(1L, user, signedInWith));

        store.advanceAuthoritiesVersion();

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication().getName()).isEqualTo(user);
    }

    /** What a passkey leaves in the session: the name of the account and nothing else of it. */
    @Test
    @DisplayName("a principal that only names the account says nothing of its password, and the session goes on with the account")
    void aPrincipalThatOnlyNamesTheAccount() {
        MockHttpServletRequest request = sessionOf(signedInWithPassword(null, user, null));
        when(accounts.loadUserByUsername(user)).thenReturn(signedInWithPassword(1L, user, LocalDateTime.of(2026, 11, 1, 9, 0)));

        store.advanceAuthoritiesVersion();

        Authentication refreshed = repository.loadDeferredContext(nextRequest(request)).get().getAuthentication();
        assertThat(refreshed.getName()).isEqualTo(user);
        assertThat(((UnifiedCustomUserDetails) refreshed.getPrincipal()).getAccount().getId()).isEqualTo(1L);
    }

    @Test
    @DisplayName("a right given reaches the open session")
    void aRightGiven() {
        MockHttpServletRequest request = signedInSession("ROLE_USER");
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, true, false, "ROLE_USER", "ROLE_READER"));

        store.advanceAuthoritiesVersion();

        assertThat(authoritiesOf(nextRequest(request))).contains("ROLE_READER");
    }

    @Test
    @DisplayName("the new rights are what a CHALLENGE narrows and what its release brings back")
    void aDecisionWorksOnTheNewRights() {
        MockHttpServletRequest request = signedInSession("ROLE_USER", "ROLE_KEEPER");
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, true, false, "ROLE_USER"));
        actions.saveAction(user, ZeroTrustAction.CHALLENGE, Map.of());
        assertThat(authoritiesOf(nextRequest(request))).containsExactly(ZeroTrustAction.CHALLENGE.getGrantedAuthority());

        store.advanceAuthoritiesVersion();
        service.invalidateDecisionCache(user);
        assertThat(authoritiesOf(nextRequest(request))).containsExactly(ZeroTrustAction.CHALLENGE.getGrantedAuthority());

        actions.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);
        service.invalidateDecisionCache(user);
        assertThat(authoritiesOf(nextRequest(request))).contains("ROLE_USER").doesNotContain("ROLE_KEEPER");
    }

    @Test
    @DisplayName("a disabled account ends the session")
    void aDisabledAccount() {
        MockHttpServletRequest request = signedInSession("ROLE_USER");
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, false, false, "ROLE_USER"));

        store.advanceAuthoritiesVersion();

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    @DisplayName("an account that is gone ends the session")
    void anAccountGone() {
        MockHttpServletRequest request = signedInSession("ROLE_USER");
        when(accounts.loadUserByUsername(user)).thenThrow(new UsernameNotFoundException("gone"));

        store.advanceAuthoritiesVersion();

        assertThat(repository.loadDeferredContext(nextRequest(request)).get().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("an account that signs in elsewhere only is no disabled account")
    void anExternalAccountIsNotDisabled() {
        MockHttpServletRequest request = signedInSession("ROLE_USER");
        when(accounts.loadUserByUsername(user)).thenReturn(account(user, true, true, "ROLE_USER"));

        store.advanceAuthoritiesVersion();

        assertThat(authoritiesOf(nextRequest(request))).contains("ROLE_USER");
    }

    @Test
    @DisplayName("a database that fails signs nobody out, and the next request tries again")
    void aFailingDatabaseSignsNobodyOut() {
        MockHttpServletRequest request = signedInSession("ROLE_USER", "ROLE_KEEPER");
        when(accounts.loadUserByUsername(user)).thenThrow(new DataAccessResourceFailureException("database down"))
                .thenReturn(account(user, true, false, "ROLE_USER"));

        store.advanceAuthoritiesVersion();

        assertThat(authoritiesOf(nextRequest(request))).contains("ROLE_KEEPER");
        assertThat(authoritiesOf(nextRequest(request))).doesNotContain("ROLE_KEEPER");
    }

    @Test
    @DisplayName("a principal of the application's own is left as it is")
    void aPrincipalOfTheApplication() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", new SecurityContextImpl(
                new UsernamePasswordAuthenticationToken(user, "unused", List.of(new SimpleGrantedAuthority("ROLE_APP")))));

        store.advanceAuthoritiesVersion();

        assertThat(authoritiesOf(request)).contains("ROLE_APP");
        verify(accounts, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("the account is read as Contexa's own work, so a request does not wait for the database behind it")
    void theAccountIsReadAsContexasOwnWork() {
        MockHttpServletRequest request = signedInSession("ROLE_USER", "ROLE_KEEPER");
        List<Boolean> inContexaWork = new ArrayList<>();
        when(accounts.loadUserByUsername(user)).thenAnswer(call -> {
            inContexaWork.add(RequestPathScope.inContexaWork());
            return account(user, true, false, "ROLE_USER");
        });

        store.advanceAuthoritiesVersion();

        assertThat(authoritiesOf(nextRequest(request))).doesNotContain("ROLE_KEEPER");
        assertThat(inContexaWork).containsExactly(true);
        assertThat(RequestPathScope.inContexaWork()).isFalse();
    }
}
