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
import io.contexa.contexaidentity.security.agent.OAuth2AgentTokenRevoker;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A5-3: a stopped agent's tokens are revoked on Contexa's authorization server, those it holds for the
 * person and its own, with a refresh token or none (token exchange and client credentials issue none). The person's
 * tokens through another client stay, and a revoked or expired authorization is not counted again.
 */
class OAuth2AgentTokenRevokerTest {

    private JdbcTemplate jdbc;
    private JdbcOAuth2AuthorizationService store;
    private OAuth2AgentTokenRevoker revoker;
    private RegisteredClient agentClient;
    private RegisteredClient portalClient;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        jdbc = new JdbcTemplate(dataSource);
        new ResourceDatabasePopulator(new ClassPathResource("contexa-oauth2-authorization-schema.sql"))
                .execute(dataSource);
        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(jdbc);
        agentClient = client("report-client");
        portalClient = client("portal-client");
        clients.save(agentClient);
        clients.save(portalClient);
        store = new JdbcOAuth2AuthorizationService(jdbc, clients);
        AuthContextProperties properties = new AuthContextProperties();
        properties.setAllowMultipleLogins(true);
        revoker = new OAuth2AgentTokenRevoker(new DeviceAwareOAuth2AuthorizationService(store, jdbc, properties),
                clients);
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("SHUTDOWN");
    }

    @Test
    void theTokensTheAgentsClientHoldsForThePersonAreRevokedAndThePersonsOwnStay() {
        Instant now = Instant.now();
        store.save(authorization("exchange", agentClient, "alice", AuthorizationGrantType.TOKEN_EXCHANGE, now, false));
        store.save(authorization("agent-login", agentClient, "alice", AuthorizationGrantType.REFRESH_TOKEN, now, true));
        store.save(authorization("own-login", portalClient, "alice", AuthorizationGrantType.REFRESH_TOKEN, now, true));
        store.save(authorization("expired", agentClient, "alice", AuthorizationGrantType.TOKEN_EXCHANGE,
                now.minusSeconds(7200), false));
        store.save(authorization("own-token", agentClient, "report-client", AuthorizationGrantType.CLIENT_CREDENTIALS,
                now, false));

        assertThat(revoker.revoke("alice", "report-client")).isEqualTo(2);

        assertThat(store.findById("exchange").getAccessToken().isInvalidated()).isTrue();
        assertThat(store.findById("agent-login").getAccessToken().isInvalidated()).isTrue();
        assertThat(store.findById("agent-login").getRefreshToken().isInvalidated()).isTrue();
        assertThat(store.findById("own-login").getAccessToken().isInvalidated()).isFalse();
        assertThat(store.findById("own-token").getAccessToken().isInvalidated()).isFalse();
        // A revoked authorization is not revoked again.
        assertThat(revoker.revoke("alice", "report-client")).isZero();
    }

    @Test
    void anAgentsOwnClientCredentialsTokensAreRevoked() {
        store.save(authorization("own-token", agentClient, "report-client", AuthorizationGrantType.CLIENT_CREDENTIALS,
                Instant.now(), false));

        assertThat(revoker.revoke("report-client", "report-client")).isEqualTo(1);
        assertThat(store.findById("own-token").getAccessToken().isInvalidated()).isTrue();
        assertThat(revoker.revoke("report-client", "unknown-client")).isZero();
        assertThat(revoker.revoke(" ", "report-client")).isZero();
    }

    private static RegisteredClient client(String clientId) {
        return RegisteredClient.withId(clientId + "-id")
                .clientId(clientId)
                .clientSecret("{noop}secret-" + clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
    }

    private static OAuth2Authorization authorization(String id, RegisteredClient client, String principal,
                                                     AuthorizationGrantType grant, Instant issuedAt,
                                                     boolean refreshToken) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName(principal)
                .authorizationGrantType(grant)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-" + id, issuedAt,
                        issuedAt.plusSeconds(3600)));
        if (refreshToken) {
            builder.refreshToken(new OAuth2RefreshToken("refresh-" + id, issuedAt, issuedAt.plusSeconds(86400)));
        }
        return builder.build();
    }
}
