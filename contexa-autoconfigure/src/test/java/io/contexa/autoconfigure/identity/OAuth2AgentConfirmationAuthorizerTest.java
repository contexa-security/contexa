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

import io.contexa.contexacommon.jdbc.LibraryTableNames;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.agent.SignedAgentConfirmationAuthorizer;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexaidentity.security.agent.OAuth2AgentConfirmationAuthorizer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A5-2: a person's approval is an authorization of Contexa's authorization server, granted by the person
 * to the agent's client and naming the approved request; it verifies until its one use, and a changed approval does
 * not verify. An agent whose client the server does not register has its approval signed instead.
 */
class OAuth2AgentConfirmationAuthorizerTest {

    private static final Instant DECIDED = Instant.now().truncatedTo(ChronoUnit.MICROS);

    private JdbcTemplate jdbc;
    private JdbcOAuth2AuthorizationService store;
    private OAuth2AgentConfirmationAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        jdbc = new JdbcTemplate(dataSource);
        new ResourceDatabasePopulator(new ClassPathResource("contexa-oauth2-authorization-schema.sql"))
                .execute(dataSource);
        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(LibraryTableNames.wrap(jdbc));
        clients.save(RegisteredClient.withId("report-client-id")
                .clientId("report-client")
                .clientSecret("{noop}report-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .build());
        store = new JdbcOAuth2AuthorizationService(LibraryTableNames.wrap(jdbc), clients);
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "report-agent", "Report", null, "report-client",
                "carol", true));
        registry.register(new AgentRegistrationRequest(null, "outside-agent", "Outside", null, "outside-client",
                "carol", true));
        authorizer = new OAuth2AgentConfirmationAuthorizer(store, clients, registry,
                new SignedAgentConfirmationAuthorizer(HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                        .encodeToString("0123456789abcdef0123456789abcdef".getBytes())), "k1")));
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("SHUTDOWN");
    }

    @Test
    void theApprovalIsAnAuthorizationOfTheServerUsedOnce() {
        AgentConfirmation decided = approved("report-agent", null);
        String authorization = authorizer.authorize(decided);
        AgentConfirmation approved = approved("report-agent", authorization);

        assertThat(authorization).startsWith(OAuth2AgentConfirmationAuthorizer.PREFIX);
        OAuth2Authorization recorded = store.findById(authorization.substring(
                OAuth2AgentConfirmationAuthorizer.PREFIX.length()));
        assertThat(recorded.getAuthorizationGrantType()).isEqualTo(OAuth2AgentConfirmationAuthorizer.AGENT_CONFIRMATION);
        assertThat(recorded.getPrincipalName()).isEqualTo("alice");
        assertThat(recorded.getRegisteredClientId()).isEqualTo("report-client-id");
        assertThat(authorizer.verify(approved)).isTrue();
        // An approval naming another request does not verify.
        assertThat(authorizer.verify(new AgentConfirmation(approved.confirmationId(), null, "DELEGATED_AGENT",
                "alice", "report-agent", null, "alice", "other-hash", "POST", "/api/exports", "DECISION_CHALLENGE",
                null, null, AgentConfirmation.Status.APPROVED, DECIDED, DECIDED.plusSeconds(900), DECIDED, "alice",
                null, authorization, null))).isFalse();

        authorizer.consumed(approved.withStatus(AgentConfirmation.Status.USED, DECIDED.plusSeconds(5)));

        assertThat(authorizer.verify(approved)).isFalse();
    }

    @Test
    void anAgentTheServerDoesNotRegisterHasItsApprovalSigned() {
        AgentConfirmation decided = approved("outside-agent", null);
        String authorization = authorizer.authorize(decided);

        assertThat(authorization).startsWith(SignedAgentConfirmationAuthorizer.PREFIX);
        assertThat(authorizer.verify(approved("outside-agent", authorization))).isTrue();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_oauth2_authorization", Integer.class)).isZero();
    }

    private static AgentConfirmation approved(String agentId, String authorization) {
        return new AgentConfirmation("confirmation-1", null, "DELEGATED_AGENT", "alice", agentId, "DLG-1", "alice",
                "request-hash", "POST", "/api/exports?format=zip", "DECISION_CHALLENGE", "unusual export", "req-1",
                AgentConfirmation.Status.APPROVED, DECIDED.minusSeconds(60), DECIDED.plusSeconds(900), DECIDED,
                "alice", null, authorization, null);
    }
}
