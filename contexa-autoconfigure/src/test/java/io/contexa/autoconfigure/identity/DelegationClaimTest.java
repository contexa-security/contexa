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

import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent OC-1: a token an agent gets by token exchange for a person names the person's delegation that holds now,
 * so the decision reads it; without one the token is issued the same.
 */
class DelegationClaimTest {

    private final InMemoryDelegationRegistry registry = new InMemoryDelegationRegistry();
    private final AgentClientDirectory agents = (tenantId, client) -> "agent-client".equals(client)
            ? Optional.of("report-agent") : Optional.empty();

    @Test
    void anExchangedTokenNamesThePersonsHoldingDelegationToTheAgent() {
        registry.record(request("alice", "report-agent", Instant.now().minus(Duration.ofDays(3)),
                Instant.now().minus(Duration.ofDays(2))));
        AgentDelegation holding = registry.record(request("alice", "report-agent", Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600)));
        registry.record(request("bob", "report-agent", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600)));
        JwtEncodingContext context = context("agent-client", exchanged("alice"));

        IdentityOAuth2AutoConfiguration.delegationClaim(context, registry, agents);

        assertThat(context.getClaims().build().getClaims()).containsEntry("delegation_id", holding.delegationId());
    }

    @Test
    void noHoldingDelegationOrNoApprovedAgentLeavesTheTokenAsItIs() {
        AgentDelegation ended = registry.record(request("alice", "report-agent", Instant.now().minusSeconds(3600),
                Instant.now().plusSeconds(3600)));
        registry.revoke(ended.delegationId(), "alice", "done");
        JwtEncodingContext revokedOnly = context("agent-client", exchanged("alice"));
        JwtEncodingContext otherClient = context("portal", exchanged("alice"));

        IdentityOAuth2AutoConfiguration.delegationClaim(revokedOnly, registry, agents);
        IdentityOAuth2AutoConfiguration.delegationClaim(otherClient, registry, agents);

        assertThat(revokedOnly.getClaims().build().getClaims()).doesNotContainKey("delegation_id");
        assertThat(otherClient.getClaims().build().getClaims()).doesNotContainKey("delegation_id");
    }

    private static Authentication exchanged(String person) {
        return new OAuth2TokenExchangeCompositeAuthenticationToken(
                new UsernamePasswordAuthenticationToken(person, null, List.of()),
                List.of(new OAuth2TokenExchangeActor(Map.of("sub", "agent-client"))));
    }

    private static JwtEncodingContext context(String clientId, Authentication principal) {
        RegisteredClient client = RegisteredClient.withId("id-" + clientId).clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE).build();
        return JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256),
                        JwtClaimsSet.builder().subject("alice").issuedAt(Instant.now()))
                .registeredClient(client)
                .principal(principal)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
    }

    private static AgentDelegationRequest request(String person, String agent, Instant from, Instant until) {
        return new AgentDelegationRequest(null, person, agent, null, "REPORTING", null, List.of("READ"),
                List.of("HX-310"), null, null, null, from, until, null, null);
    }
}
