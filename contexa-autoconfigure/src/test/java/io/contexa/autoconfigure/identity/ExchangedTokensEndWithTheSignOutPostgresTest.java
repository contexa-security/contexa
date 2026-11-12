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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.agent.RegistryAgentClientDirectory;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.token.validator.OAuth2TokenValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What a person's sign-out ends on the database customers run, beyond the sign-in: the tokens agents got by exchanging
 * the person's token end with it, unless the person delegated to that agent, whose delegation then governs them. Another
 * person's, an agent's own sign-out of its token, and a dead token end no more than before.
 */
class ExchangedTokensEndWithTheSignOutPostgresTest {

    private PostgresTestDatabase database;
    private LocalContainerEntityManagerFactoryBean entityManagers;
    private DeviceAwareOAuth2AuthorizationService tokens;
    private RegisteredClientRepository clients;
    private RegisteredClient internal;
    private RegisteredClient reportAgent;
    private RegisteredClient delegatedAgent;
    private InMemoryAgentRegistry agents;
    private InMemoryDelegationRegistry delegations;
    private CompositeLogoutHandler signOut;
    private final TokenService transport = mock(TokenService.class);

    @BeforeEach
    void open() {
        database = PostgresTestDatabase.empty();
        JdbcTemplate jdbc = database.jdbcTemplate();
        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa");
        entityManagers.setPackagesToScan("io.contexa.autoconfigure.identity.none");
        entityManagers.afterPropertiesSet();
        TransactionTemplate transactions = new TransactionTemplate(new JpaTransactionManager(entityManagers.getObject()));

        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("https://issuer.example.test");
        properties.getOauth2().setClientSecret("postgres-test-unique-client-secret");
        properties.setAllowMultipleLogins(true);
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(transactions, properties);
        clients = configuration.registeredClientRepository(jdbc);
        internal = clients.findByClientId(properties.getOauth2().getClientId());
        reportAgent = agentClient("report-client");
        delegatedAgent = agentClient("delegated-client");
        tokens = (DeviceAwareOAuth2AuthorizationService) configuration.authorizationService(jdbc, clients);

        agents = new InMemoryAgentRegistry();
        agents.register(new AgentRegistrationRequest(null, "report-agent", "Reports", "AGENT", "report-client", "carol", true));
        agents.register(new AgentRegistrationRequest("tenant-a", "delegated-agent", "Delegated", "AGENT",
                "delegated-client", "carol", true));
        delegations = new InMemoryDelegationRegistry();
        delegations.record(new AgentDelegationRequest("tenant-a", "alice", "delegated-agent", null, "REPORTING",
                "Weekly report", List.of("READ"), List.of(), null, null, null, Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600), null, null));

        OAuth2TokenValidator validator = new OAuth2TokenValidator(null, tokens, 0);
        doAnswer(invocation -> {
            validator.invalidateRefreshToken(invocation.getArgument(0));
            return null;
        }).when(transport).invalidateRefreshToken(anyString());
        when(transport.prepareClearTokens()).thenReturn(TokenTransportResult.builder().build());
        when(transport.resolveAccessToken(any())).thenAnswer(invocation ->
                header(invocation.getArgument(0), "Authorization"));
        when(transport.resolveRefreshToken(any())).thenAnswer(invocation ->
                ((MockHttpServletRequest) invocation.getArgument(0)).getHeader("X-Refresh-Token"));
        signOut = signOutHandler(configuration, properties);
    }

    @AfterEach
    void close() {
        // Without a test database the setup is skipped before these exist; closing them then failed the test.
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    /** The sign-out Contexa configures, with the agents and delegations the application holds. */
    private CompositeLogoutHandler signOutHandler(IdentityOAuth2AutoConfiguration configuration,
                                                  AuthContextProperties properties) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("agents", new RegistryAgentClientDirectory(agents));
        beans.addBean("delegations", delegations);
        return configuration.compositeLogoutHandler(transport, properties,
                beans.getBeanProvider(ZeroTrustSecurityService.class), mock(SessionIdResolver.class), tokens,
                beans.getBeanProvider(MfaSessionRepository.class), beans.getBeanProvider(MfaStateMachineService.class),
                clients, beans.getBeanProvider(AgentClientDirectory.class),
                beans.getBeanProvider(DelegationRegistry.class));
    }

    @Test
    void theSignOutEndsTheExchangedTokensThatNoDelegationGoverns() {
        signedIn("alice-login", "alice");
        exchanged("alice-by-report", "alice", reportAgent);
        exchanged("alice-by-delegated", "alice", delegatedAgent);
        exchanged("bob-by-report", "bob", reportAgent);

        signOut.logout(signOutWith("access-alice-login", "refresh-alice-login"), new MockHttpServletResponse(), null);

        assertThat(ended("alice-login")).isTrue();
        assertThat(ended("alice-by-report")).isTrue();
        assertThat(ended("alice-by-delegated")).isFalse();
        assertThat(ended("bob-by-report")).isFalse();
    }

    @Test
    void theSignOutWithTheAccessTokenAloneEndsThemToo() {
        signedIn("alice-login", "alice");
        exchanged("alice-by-report", "alice", reportAgent);

        signOut.logout(signOutWith("access-alice-login", null), new MockHttpServletResponse(), null);

        assertThat(ended("alice-login")).isTrue();
        assertThat(ended("alice-by-report")).isTrue();
    }

    @Test
    void anAgentSigningOutItsExchangedTokenEndsThatTokenOnly() {
        signedIn("alice-login", "alice");
        exchanged("alice-by-report", "alice", reportAgent);
        exchanged("alice-by-report-2", "alice", reportAgent);

        signOut.logout(signOutWith("access-alice-by-report", null), new MockHttpServletResponse(), null);

        assertThat(ended("alice-by-report")).isTrue();
        assertThat(ended("alice-by-report-2")).isFalse();
        assertThat(ended("alice-login")).isFalse();
    }

    @Test
    void aSignOutWithADeadTokenEndsNoExchange() {
        signedIn("alice-login", "alice");
        exchanged("alice-by-report", "alice", reportAgent);

        signOut.logout(signOutWith("access-forged", "refresh-forged"), new MockHttpServletResponse(), null);

        assertThat(ended("alice-by-report")).isFalse();
        assertThat(ended("alice-login")).isFalse();
    }

    private RegisteredClient agentClient(String clientId) {
        RegisteredClient agent = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}secret-of-" + clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("reports.read")
                .build();
        clients.save(agent);
        return agent;
    }

    private void signedIn(String id, String person) {
        Instant now = Instant.now();
        tokens.save(OAuth2Authorization.withRegisteredClient(internal)
                .id(id)
                .principalName(person)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-" + id, now,
                        now.plusSeconds(3600)))
                .refreshToken(new OAuth2RefreshToken("refresh-" + id, now, now.plusSeconds(86400)))
                .build());
    }

    /** What Spring's exchange provider keeps for the token an agent's client got for the person: no refresh token. */
    private void exchanged(String id, String person, RegisteredClient agent) {
        Instant now = Instant.now();
        tokens.save(OAuth2Authorization.withRegisteredClient(agent)
                .id(id)
                .principalName(person)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-" + id, now,
                        now.plusSeconds(3600)))
                .build());
    }

    private boolean ended(String id) {
        return tokens.findById(id).getAccessToken().isInvalidated();
    }

    private static MockHttpServletRequest signOutWith(String accessToken, String refreshToken) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        request.addHeader("Authorization", "Bearer " + accessToken);
        if (refreshToken != null) {
            request.addHeader("X-Refresh-Token", refreshToken);
        }
        return request;
    }

    private static String header(MockHttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value != null && value.startsWith("Bearer ") ? value.substring(7) : null;
    }
}
