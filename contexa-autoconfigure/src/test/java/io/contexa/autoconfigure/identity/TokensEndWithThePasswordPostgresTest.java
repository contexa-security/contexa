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
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.service.UserAccountChangeListener;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.handler.logout.LogoutStrategy;
import io.contexa.contexaidentity.security.token.service.TokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
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
import org.springframework.transaction.event.TransactionalEventListenerFactory;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * What a new password ends on the database customers run, with the transaction manager they run: the tokens end in the
 * listener that runs after the commit of the change, where the finished transaction is still bound to the thread, and a
 * write that joins it is no write of anybody's.
 */
class TokensEndWithThePasswordPostgresTest {

    private PostgresTestDatabase database;
    private LocalContainerEntityManagerFactoryBean entityManagers;
    private AnnotationConfigApplicationContext listening;
    private JdbcTemplate jdbc;
    private TransactionTemplate transactions;
    private DeviceAwareOAuth2AuthorizationService tokens;
    private RegisteredClient client;

    @BeforeEach
    void open() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa");
        entityManagers.setPackagesToScan("io.contexa.autoconfigure.identity.none");
        entityManagers.afterPropertiesSet();
        transactions = new TransactionTemplate(new JpaTransactionManager(entityManagers.getObject()));

        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("https://issuer.example.test");
        properties.getOauth2().setClientSecret("postgres-test-unique-client-secret");
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(transactions, properties);
        RegisteredClientRepository clients = configuration.registeredClientRepository(jdbc);
        client = clients.findByClientId(properties.getOauth2().getClientId());
        tokens = (DeviceAwareOAuth2AuthorizationService) configuration.authorizationService(jdbc, clients);

        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("forceLogout",
                new CompositeLogoutHandler(List.of(mock(LogoutStrategy.class)), mock(TokenService.class), null, tokens));
        listening = new AnnotationConfigApplicationContext();
        listening.registerBean(TransactionalEventListenerFactory.class);
        listening.registerBean(UserAccountChangeListener.class,
                () -> new UserAccountChangeListener(beans.getBeanProvider(SecurityContextDataStore.class),
                        beans.getBeanProvider(IForceLogoutService.class)));
        listening.refresh();
    }

    @AfterEach
    void close() {
        listening.close();
        entityManagers.destroy();
        database.close();
    }

    private void issued(String id, String principal, AuthorizationGrantType grant, boolean refreshToken) {
        Instant now = Instant.now();
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName(principal)
                .authorizationGrantType(grant)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-" + id, now,
                        now.plusSeconds(3600)));
        if (refreshToken) {
            builder.refreshToken(new OAuth2RefreshToken("refresh-" + id, now, now.plusSeconds(86400)));
        }
        tokens.save(builder.build());
    }

    /** What the change of a password does: a write in its own transaction, and the event in that transaction. */
    private void passwordChanged(String user, boolean commit) {
        transactions.executeWithoutResult(status -> {
            jdbc.update("update ctxa_oauth2_authorization set attributes = attributes where principal_name = ?", user);
            listening.publishEvent(new UserPasswordChangedEvent(user));
            if (!commit) {
                status.setRollbackOnly();
            }
        });
    }

    private boolean accessEnded(String id) {
        return tokens.findById(id).getAccessToken().isInvalidated();
    }

    @Test
    @DisplayName("a committed password ends the sign-ins of the user, the access token and the refresh token")
    void theSignInsEnd() {
        issued("alice-login", "alice", AuthorizationGrantType.REFRESH_TOKEN, true);

        passwordChanged("alice", true);

        assertThat(accessEnded("alice-login")).isTrue();
        assertThat(tokens.findById("alice-login").getRefreshToken().isInvalidated()).isTrue();
    }

    @Test
    @DisplayName("what was issued for the user without a refresh token ends as well: an agent's delegated token")
    void aDelegatedTokenEnds() {
        issued("alice-exchange", "alice", AuthorizationGrantType.TOKEN_EXCHANGE, false);

        passwordChanged("alice", true);

        assertThat(accessEnded("alice-exchange")).isTrue();
    }

    @Test
    @DisplayName("the tokens of another user stay")
    void anotherUserStays() {
        issued("alice-login", "alice", AuthorizationGrantType.REFRESH_TOKEN, true);
        issued("bob-login", "bob", AuthorizationGrantType.REFRESH_TOKEN, true);

        passwordChanged("alice", true);

        assertThat(accessEnded("bob-login")).isFalse();
    }

    @Test
    @DisplayName("a change rolled back ends nothing")
    void aRollbackEndsNothing() {
        issued("alice-login", "alice", AuthorizationGrantType.REFRESH_TOKEN, true);

        passwordChanged("alice", false);

        assertThat(accessEnded("alice-login")).isFalse();
    }
}
