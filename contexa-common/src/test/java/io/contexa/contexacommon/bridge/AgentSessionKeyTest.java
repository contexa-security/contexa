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
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.AgentSessionKey;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A1-11: an agent's or a client's token request is grouped within that agent: by the login session its token carries,
 * else its delegation, else the token. A person's token and a request without a token have no agent session.
 */
class AgentSessionKeyTest {

    @AfterEach
    void reset() {
        AgentSessionKey.configure(null);
    }

    @Test
    void aPersonsTokenHasNoAgentSession() {
        assertThat(AgentSessionKey.of(token(Map.of("sub", "alice", "sid", "login-1", "client_id", "web")))).isNull();
        assertThat(AgentSessionKey.of(UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()))).isNull();
        assertThat(AgentSessionKey.of(null)).isNull();
    }

    @Test
    void anExchangedTokenIsGroupedWithinItsAgentNotWithThePersonsLogin() {
        String agentX = AgentSessionKey.of(token(Map.of("sub", "alice", "sid", "login-1",
                "act", Map.of("sub", "agent-x"))));
        String agentY = AgentSessionKey.of(token(Map.of("sub", "alice", "sid", "login-1",
                "act", Map.of("sub", "agent-y"))));

        assertThat(agentX).startsWith("agent:sid:").isNotEqualTo(agentY);
        assertThat(agentX).doesNotContain("login-1");
        assertThat(AgentSessionKey.of(token(Map.of("sub", "alice", "sid", "login-1", "act", Map.of("sub", "agent-x")))))
                .isEqualTo(agentX);
    }

    @Test
    void theDelegationComesBeforeTheTokenWhenTheTokenCarriesNoLogin() {
        String byDelegation = AgentSessionKey.of(token(Map.of("sub", "alice", "act", Map.of("sub", "agent-x"),
                "delegation_id", "dlg-7", "jti", "token-1")));
        String sameDelegationOtherToken = AgentSessionKey.of(token(Map.of("sub", "alice",
                "act", Map.of("sub", "agent-x"), "delegation_id", "dlg-7", "jti", "token-2")));

        assertThat(byDelegation).startsWith("agent:delegation:").isEqualTo(sameDelegationOtherToken);
    }

    @Test
    void aClientsOwnTokenIsGroupedByTheTokenWithinThatClient() {
        String first = AgentSessionKey.of(token(Map.of("sub", "report-client", "client_id", "report-client",
                "jti", "token-1")));
        String other = AgentSessionKey.of(token(Map.of("sub", "batch-client", "client_id", "batch-client",
                "jti", "token-1")));

        assertThat(first).startsWith("client:jti:").isNotEqualTo(other);
        assertThat(AgentSessionKey.of(token(Map.of("sub", "report-client", "client_id", "report-client")))).isNull();
    }

    @Test
    void configuredClaimNamesAreUsed() {
        BridgeProperties.Delegation.Token settings = new BridgeProperties.Delegation.Token();
        settings.setDelegationIdClaims(List.of("grant_ref"));
        AgentSessionKey.configure(settings);

        assertThat(AgentSessionKey.of(token(Map.of("sub", "alice", "act", Map.of("sub", "agent-x"),
                "grant_ref", "g-1", "jti", "token-1")))).startsWith("agent:delegation:");
    }

    private static JwtAuthenticationToken token(Map<String, Object> claims) {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").claims(values -> values.putAll(claims))
                .issuedAt(Instant.parse("2026-10-23T00:00:00Z")).expiresAt(Instant.parse("2026-10-23T01:00:00Z"))
                .build();
        return new JwtAuthenticationToken(jwt, List.of());
    }
}
