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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.signal.RiskSignalReceiver;
import io.contexa.contexacore.autonomous.signal.SecurityEventToken;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.handler.logout.LogoutStrategy;
import io.contexa.contexaidentity.security.token.service.TokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * What a risk signal ends on the database customers run: an event that ends sessions ends the tokens of the subject as
 * well, or the access token that runs out is renewed with the refresh token and the subject goes on.
 */
class TokensEndWithARiskSignalPostgresTest {

    private PostgresTestDatabase database;
    private LocalContainerEntityManagerFactoryBean entityManagers;
    private DeviceAwareOAuth2AuthorizationService tokens;
    private RegisteredClient client;
    private InMemoryZeroTrustActionRepository actions;
    private RiskSignalReceiver receiver;

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
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(transactions, properties);
        RegisteredClientRepository clients = configuration.registeredClientRepository(jdbc);
        client = clients.findByClientId(properties.getOauth2().getClientId());
        tokens = (DeviceAwareOAuth2AuthorizationService) configuration.authorizationService(jdbc, clients);

        actions = new InMemoryZeroTrustActionRepository();
        InMemoryZeroTrustSecurityService sessions = new InMemoryZeroTrustSecurityService(mock(ThreatScoreUtil.class),
                new SecurityZeroTrustProperties(), actions, new InMemoryBlockingSignalBroadcaster());
        CompositeLogoutHandler forceLogout = new CompositeLogoutHandler(List.of(mock(LogoutStrategy.class)),
                mock(TokenService.class), sessions, tokens);
        receiver = new RiskSignalReceiver(actions, sessions, subject -> RiskSignalReceiver.userOf(subject, null), null,
                forceLogout);
    }

    @AfterEach
    void close() {
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    private void issued(String id, String principal, AuthorizationGrantType grant, boolean refreshToken) {
        Instant now = Instant.now();
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName(principal)
                .authorizationGrantType(grant)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-" + id, now,
                        now.plus(Duration.ofHours(1))));
        if (refreshToken) {
            builder.refreshToken(new OAuth2RefreshToken("refresh-" + id, now, now.plus(Duration.ofDays(1))));
        }
        tokens.save(builder.build());
    }

    private void signal(String jti, String eventType, String user) {
        receiver.receive(new SecurityEventToken("https://idp.example.test", jti, Instant.now(),
                Map.of("format", "iss_sub", "iss", "https://idp.example.test", "sub", user),
                Map.of(eventType, Map.of())));
    }

    private boolean refreshEnded(String id) {
        return tokens.findById(id).getRefreshToken().isInvalidated();
    }

    private boolean accessEnded(String id) {
        return tokens.findById(id).getAccessToken().isInvalidated();
    }

    @Test
    @DisplayName("a revoked session ends the sign-ins of the subject, the refresh token and the access token")
    void aRevokedSession() {
        issued("alice-login", "alice", AuthorizationGrantType.REFRESH_TOKEN, true);

        signal("jti-1", SecurityEventToken.SESSION_REVOKED, "alice");

        assertThat(refreshEnded("alice-login")).isTrue();
        assertThat(accessEnded("alice-login")).isTrue();
    }

    @Test
    @DisplayName("a compromised credential, a disabled and a purged account end the tokens too")
    void everyEventThatEndsSessions() {
        issued("carol-login", "carol", AuthorizationGrantType.REFRESH_TOKEN, true);
        issued("dave-login", "dave", AuthorizationGrantType.REFRESH_TOKEN, true);
        issued("erin-login", "erin", AuthorizationGrantType.REFRESH_TOKEN, true);

        signal("jti-2", SecurityEventToken.CREDENTIAL_COMPROMISE, "carol");
        signal("jti-3", SecurityEventToken.ACCOUNT_DISABLED, "dave");
        signal("jti-4", SecurityEventToken.ACCOUNT_PURGED, "erin");

        assertThat(refreshEnded("carol-login")).isTrue();
        assertThat(refreshEnded("dave-login")).isTrue();
        assertThat(refreshEnded("erin-login")).isTrue();
    }

    @Test
    @DisplayName("what an agent's client got for the subject by token exchange ends as well")
    void aDelegatedToken() {
        issued("alice-exchange", "alice", AuthorizationGrantType.TOKEN_EXCHANGE, false);

        signal("jti-5", SecurityEventToken.SESSION_REVOKED, "alice");

        assertThat(accessEnded("alice-exchange")).isTrue();
    }

    @Test
    @DisplayName("a restriction in force stays when the tokens end")
    void aRestrictionStays() {
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        issued("alice-login", "alice", AuthorizationGrantType.REFRESH_TOKEN, true);

        signal("jti-6", SecurityEventToken.CREDENTIAL_COMPROMISE, "alice");

        assertThat(refreshEnded("alice-login")).isTrue();
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("control: an event that only has the subject decided again ends no token, and the tokens of another stay")
    void whatDoesNotEndTokens() {
        issued("alice-login", "alice", AuthorizationGrantType.REFRESH_TOKEN, true);
        issued("bob-login", "bob", AuthorizationGrantType.REFRESH_TOKEN, true);

        signal("jti-7", SecurityEventToken.RISK_LEVEL_CHANGE, "alice");
        signal("jti-8", SecurityEventToken.SESSION_REVOKED, "carol");

        assertThat(refreshEnded("alice-login")).isFalse();
        assertThat(refreshEnded("bob-login")).isFalse();
    }
}
