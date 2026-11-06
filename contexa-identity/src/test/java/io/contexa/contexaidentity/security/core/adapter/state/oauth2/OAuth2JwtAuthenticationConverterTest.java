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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.beans.factory.ObjectProvider;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.agent.RegistryAgentClientDirectory;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2JwtAuthenticationConverterTest {

    @Mock
    private HttpSecurity httpSecurity;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private UserDetailsService userDetailsService;
    @Mock
    private UserDetails userDetails;

    private OAuth2JwtAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        when(httpSecurity.getSharedObject(ApplicationContext.class)).thenReturn(applicationContext);
        ObjectProvider<UserDetailsService> applicationStore = mock(ObjectProvider.class);
        when(applicationStore.getIfUnique()).thenReturn(userDetailsService);
        when(applicationContext.getBeanProvider(UserDetailsService.class)).thenReturn(applicationStore);
        ObjectProvider<AuthContextProperties> provider = mock(ObjectProvider.class);
        when(applicationContext.getBeanProvider(AuthContextProperties.class)).thenReturn(provider);

        converter = new OAuth2JwtAuthenticationConverter(httpSecurity);
    }

    @Test
    void aRoleTakenFromTheAccountStaysOutOfATokenThatStillNamesIt() {
        Jwt jwt = userJwt("user1", "read", "roles", List.of("ADMIN", "USER", "SCOPE_read"));
        stubUserDetails("user1", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(extractAuthorityStrings(converter.convert(jwt))).containsExactlyInAnyOrder("ROLE_USER", "SCOPE_read");
    }

    @Test
    void aRoleClaimWrittenWithItsPrefixAddsNothingEither() {
        Jwt jwt = buildJwt("user1", "roles", List.of("ROLE_ADMIN"));
        stubUserDetails("user1", List.of());

        assertThat(extractAuthorityStrings(converter.convert(jwt))).isEmpty();
    }

    @Test
    void anAuthoritiesClaimAddsNothingTheAccountDoesNotHold() {
        Jwt jwt = buildJwt("user1", "authorities", List.of("READ_PRIVILEGE", "WRITE_PRIVILEGE"));
        stubUserDetails("user1", List.of(new SimpleGrantedAuthority("READ_PRIVILEGE")));

        assertThat(extractAuthorityStrings(converter.convert(jwt))).containsExactly("READ_PRIVILEGE");
    }

    @Test
    void aScopeNamedInARoleClaimIsNoScope() {
        Jwt jwt = buildJwt("user1", "authorities", List.of("SCOPE_admin"));
        stubUserDetails("user1", List.of());

        assertThat(extractAuthorityStrings(converter.convert(jwt))).isEmpty();
    }

    @Test
    void theAccountsAuthoritiesAndTheTokensScopesMakeTheAuthentication() {
        Jwt jwt = userJwt("user1", "read reports.write", "roles", List.of("USER"));
        stubUserDetails("user1", List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ORDER_READ")));

        assertThat(extractAuthorityStrings(converter.convert(jwt)))
                .containsExactlyInAnyOrder("ROLE_USER", "ORDER_READ", "SCOPE_read", "SCOPE_reports.write");
    }

    @Test
    void theAccountIsReadForEveryRequest() {
        Jwt jwt = userJwt("user1", "read", "roles", List.of("ADMIN"));
        stubUserDetails("user1", List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(extractAuthorityStrings(converter.convert(jwt))).contains("ROLE_ADMIN");

        stubUserDetails("user1", List.of());

        assertThat(extractAuthorityStrings(converter.convert(jwt))).containsExactly("SCOPE_read");
    }

    @Test
    void aDisabledAccountsTokenIsRefusedAsItsSessionWouldEnd() {
        when(userDetailsService.loadUserByUsername("user1")).thenReturn(account(false, false, false));

        assertThatThrownBy(() -> converter.convert(userJwt("user1", "read", "roles", List.of("USER"))))
                .isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void anApplicationsDisabledUserIsRefusedToo() {
        when(userDetailsService.loadUserByUsername("user1"))
                .thenReturn(User.withUsername("user1").password("{noop}x").disabled(true).build());

        assertThatThrownBy(() -> converter.convert(userJwt("user1", "read", "roles", List.of("USER"))))
                .isInstanceOf(InvalidBearerTokenException.class);
    }

    /** UserDetails.isEnabled() is false for such an account, so that it cannot sign in with a password here. */
    @Test
    void anAccountThatSignsInElsewhereOnlyIsNoDisabledAccount() {
        when(userDetailsService.loadUserByUsername("user1")).thenReturn(account(true, true, false));

        assertThat(extractAuthorityStrings(converter.convert(userJwt("user1", "read", "roles", List.of("USER")))))
                .containsExactlyInAnyOrder("ROLE_USER", "SCOPE_read");
    }

    /** Failed passwords lock an account: anyone can do that to a user, so it ends no token that is out, as no session. */
    @Test
    void aLockedAccountsTokenGoesOnAsItsSessionDoes() {
        when(userDetailsService.loadUserByUsername("user1")).thenReturn(account(true, false, true));

        assertThat(extractAuthorityStrings(converter.convert(userJwt("user1", "read", "roles", List.of("USER")))))
                .containsExactlyInAnyOrder("ROLE_USER", "SCOPE_read");
    }

    /** An identity provider's token: its roles were never read without an account, and still are not. */
    @Test
    void aForeignTokenWithRoleClaimsAndNoAccountIsRefused() {
        when(userDetailsService.loadUserByUsername("someone")).thenThrow(new UsernameNotFoundException("none"));

        assertThatThrownBy(() -> converter.convert(userJwt("someone", "read", "roles", List.of("ADMIN"))))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void convert_shouldThrowOnNullSubject() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("roles", List.of("ADMIN"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();

        assertThatThrownBy(() -> converter.convert(jwt))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anApprovedAgentClientsOwnTokenAuthenticatesWithTheTokensScopesOnly() {
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(),
                (tenantId, clientId) -> "report-client".equals(clientId) ? Optional.of("report-bot") : Optional.empty());
        when(userDetailsService.loadUserByUsername("report-client")).thenThrow(new UsernameNotFoundException("none"));

        Jwt withRoleClaim = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claims(claims -> claims.putAll(Map.of("sub", "report-client", "client_id", "report-client",
                        "scope", "reports.read", "roles", List.of("ADMIN"))))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
        AbstractAuthenticationToken token = clientAware.convert(withRoleClaim);

        assertThat(token).isInstanceOf(JwtAuthenticationToken.class);
        assertThat(token.getName()).isEqualTo("report-client");
        assertThat(extractAuthorityStrings(token)).containsExactly("SCOPE_reports.read");
    }

    @Test
    void anApprovedAgentClientNamedLikeAPersonCarriesItsScopesAndNothingOfThePerson() {
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(),
                (tenantId, clientId) -> "alice".equals(clientId) ? Optional.of("report-bot") : Optional.empty());
        stubUserDetails("alice", List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        assertThat(extractAuthorityStrings(clientAware.convert(clientJwt("alice", "alice", "reports.read"))))
                .containsExactly("SCOPE_reports.read");
    }

    @Test
    void theInternalClientsOwnTokenIsRefusedEvenWhenTheDirectoryWouldNameIt() {
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(),
                (tenantId, clientId) -> Optional.of("any-agent"));
        when(userDetailsService.loadUserByUsername("default-client")).thenThrow(new UsernameNotFoundException("none"));

        assertThatThrownBy(() -> clientAware.convert(clientJwt("default-client", "default-client", "read")))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void aClientNeitherApprovedNorListedIsRefused() {
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(), AgentClientDirectory.NONE);
        when(userDetailsService.loadUserByUsername("stray-client")).thenThrow(new UsernameNotFoundException("none"));

        assertThatThrownBy(() -> clientAware.convert(clientJwt("stray-client", "stray-client", "read")))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void aServiceClientListedInTheSettingsAuthenticatesWithItsScopes() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setServiceClientIds(List.of("batch-client"));
        OAuth2JwtAuthenticationConverter clientAware = converterWith(properties, AgentClientDirectory.NONE);
        when(userDetailsService.loadUserByUsername("batch-client")).thenThrow(new UsernameNotFoundException("none"));

        AbstractAuthenticationToken token = clientAware.convert(clientJwt("batch-client", "batch-client", "jobs.run"));

        assertThat(token.getName()).isEqualTo("batch-client");
        assertThat(extractAuthorityStrings(token)).containsExactly("SCOPE_jobs.run");
    }

    @Test
    void aDelegatedTokenWhoseUserHasNoAccountIsRefused() {
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(),
                (tenantId, clientId) -> Optional.of("report-bot"));
        when(userDetailsService.loadUserByUsername("ghost")).thenThrow(new UsernameNotFoundException("none"));

        assertThatThrownBy(() -> clientAware.convert(clientJwt("ghost", "report-client", "reports.read")))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void aUsersTokenStillTakesTheUsersAuthoritiesWhenClientPrincipalsAreConfigured() {
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(),
                (tenantId, clientId) -> Optional.of("report-bot"));
        stubUserDetails("alice", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        AbstractAuthenticationToken token = clientAware.convert(clientJwt("alice", "report-client", "reports.read"));

        assertThat(extractAuthorityStrings(token)).contains("ROLE_USER", "SCOPE_reports.read");
    }

    /**
     * docs/agent A5-3: every token of a suspended agent is refused, its own and those it holds for a person; a person's
     * token through another client still works.
     */
    @Test
    void everyTokenOfASuspendedAgentIsRefused() {
        AgentClientDirectory directory = new AgentClientDirectory() {
            @Override
            public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                return "sync-client".equals(clientId) || "report-client".equals(clientId)
                        ? Optional.of(clientId.replace("-client", "-agent")) : Optional.empty();
            }

            @Override
            public boolean suspendedAgentClient(String tenantId, String clientId) {
                return "sync-client".equals(clientId);
            }
        };
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(), directory);
        stubUserDetails("alice", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThatThrownBy(() -> clientAware.convert(clientJwt("sync-client", "sync-client", "sync.run")))
                .isInstanceOf(InvalidBearerTokenException.class);
        assertThatThrownBy(() -> clientAware.convert(clientJwt("alice", "sync-client", "reports.read")))
                .isInstanceOf(InvalidBearerTokenException.class);
        assertThat(extractAuthorityStrings(clientAware.convert(clientJwt("alice", "report-client", "reports.read"))))
                .contains("ROLE_USER", "SCOPE_reports.read");
    }

    /**
     * A token Contexa issues names no tenant: the token an agent registered in a tenant holds for a person is refused once
     * the agent is suspended there, as the token of an agent of no tenant is.
     */
    @Test
    void theTokenASuspendedAgentOfATenantHoldsForAPersonIsRefused() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest("tenant-a", "tenant-bot", "Tenant bot", "AGENT", "tenant-client",
                "carol", true));
        OAuth2JwtAuthenticationConverter clientAware = converterWith(new AuthContextProperties(),
                new RegistryAgentClientDirectory(registry));
        stubUserDetails("alice", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(extractAuthorityStrings(clientAware.convert(clientJwt("alice", "tenant-client", "reports.read"))))
                .contains("ROLE_USER");
        registry.suspend("tenant-a", "tenant-bot", "stopped");

        assertThatThrownBy(() -> clientAware.convert(clientJwt("alice", "tenant-client", "reports.read")))
                .isInstanceOf(InvalidBearerTokenException.class);
    }

    // -- helper methods --

    private static UnifiedCustomUserDetails account(boolean enabled, boolean externalAuthOnly, boolean locked) {
        return new UnifiedCustomUserDetails(UserDto.builder().id(1L).username("user1").password("{noop}x").enabled(enabled)
                .externalAuthOnly(externalAuthOnly).accountLocked(locked).build(),
                Set.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private Jwt userJwt(String subject, String scope, String claimName, List<String> claimValues) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(subject)
                .claim("scope", scope)
                .claim(claimName, claimValues)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    private Jwt buildJwt(String subject, String claimName, List<String> claimValues) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(subject)
                .claim(claimName, claimValues)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    @SuppressWarnings("unchecked")
    private OAuth2JwtAuthenticationConverter converterWith(AuthContextProperties properties,
                                                          AgentClientDirectory directory) {
        properties.setOauth2ServerMode(OAuth2ServerMode.RESOURCE_SERVER);
        ApplicationContext context = mock(ApplicationContext.class);
        HttpSecurity http = mock(HttpSecurity.class);
        when(http.getSharedObject(ApplicationContext.class)).thenReturn(context);
        ObjectProvider<UserDetailsService> applicationStore = mock(ObjectProvider.class);
        when(applicationStore.getIfUnique()).thenReturn(userDetailsService);
        when(context.getBeanProvider(UserDetailsService.class)).thenReturn(applicationStore);
        ObjectProvider<AuthContextProperties> propertiesProvider = mock(ObjectProvider.class);
        when(propertiesProvider.getIfAvailable()).thenReturn(properties);
        when(context.getBeanProvider(AuthContextProperties.class)).thenReturn(propertiesProvider);
        ObjectProvider<AgentClientDirectory> directoryProvider = mock(ObjectProvider.class);
        when(directoryProvider.getIfAvailable()).thenReturn(directory);
        when(context.getBeanProvider(AgentClientDirectory.class)).thenReturn(directoryProvider);
        ObjectProvider<BridgeProperties> bridgeProvider = mock(ObjectProvider.class);
        when(bridgeProvider.getIfAvailable()).thenReturn(new BridgeProperties());
        when(context.getBeanProvider(BridgeProperties.class)).thenReturn(bridgeProvider);
        return new OAuth2JwtAuthenticationConverter(http);
    }

    private Jwt clientJwt(String subject, String clientId, String scope) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claims(claims -> claims.putAll(Map.of("sub", subject, "client_id", clientId, "scope", scope)))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    @SuppressWarnings("unchecked")
    private void stubUserDetails(String username, List<? extends GrantedAuthority> authorities) {
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(userDetails.isEnabled()).thenReturn(true);
        when(userDetails.getAuthorities()).thenReturn((Collection) authorities);
    }

    private Collection<String> extractAuthorityStrings(AbstractAuthenticationToken token) {
        return token.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
