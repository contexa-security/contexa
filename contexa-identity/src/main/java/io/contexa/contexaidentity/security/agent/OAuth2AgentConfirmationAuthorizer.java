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
package io.contexa.contexaidentity.security.agent;

import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Records a person's approval of an agent's request as an authorization of Contexa's authorization server (docs/agent
 * A5-2, IETF AIMS 10.7): an authorization of the agent's registered client, granted by the person who approved,
 * naming the approved request ({@value #REQUEST_HASH}) and spent once the request ran. An agent whose client this
 * server does not register (its tokens come from another authorization server) has its approval recorded by the
 * fallback, a keyed signature.
 */
@Slf4j
public class OAuth2AgentConfirmationAuthorizer implements AgentConfirmationAuthorizer {

    /** The grant the approval's authorization is recorded under. */
    public static final AuthorizationGrantType AGENT_CONFIRMATION =
            new AuthorizationGrantType("urn:contexa:params:oauth:grant-type:agent-confirmation");
    /** The prefix of the identifiers of the authorizations this server records. */
    public static final String PREFIX = "ctxa-as:";
    static final String CONFIRMATION_ID = "agent_confirmation_id";
    static final String REQUEST_HASH = "agent_request_hash";
    static final String AGENT_ID = "agent_id";
    static final String SUBJECT = "agent_request_user";
    static final String DECIDED_AT = "agent_confirmation_decided_at";
    static final String USED_AT = "agent_confirmation_used_at";

    private final OAuth2AuthorizationService authorizations;
    private final RegisteredClientRepository clients;
    private final AgentRegistry registry;
    private final AgentConfirmationAuthorizer fallback;

    public OAuth2AgentConfirmationAuthorizer(OAuth2AuthorizationService authorizations,
                                             RegisteredClientRepository clients, @Nullable AgentRegistry registry,
                                             AgentConfirmationAuthorizer fallback) {
        this.authorizations = Objects.requireNonNull(authorizations, "authorizations");
        this.clients = Objects.requireNonNull(clients, "clients");
        this.registry = registry;
        this.fallback = Objects.requireNonNull(fallback, "fallback");
    }

    @Override
    public String authorize(AgentConfirmation approved) {
        RegisteredClient client = agentClient(approved);
        if (client == null) {
            return fallback.authorize(approved);
        }
        String id = UUID.randomUUID().toString();
        authorizations.save(OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName(Objects.toString(approved.decidedBy(), approved.recipientId()))
                .authorizationGrantType(AGENT_CONFIRMATION)
                .attribute(CONFIRMATION_ID, approved.confirmationId())
                .attribute(REQUEST_HASH, approved.requestHash())
                .attribute(AGENT_ID, approved.agentId())
                .attribute(SUBJECT, approved.userId())
                .attribute(DECIDED_AT, String.valueOf(approved.decidedAt()))
                .build());
        return PREFIX + id;
    }

    @Override
    public boolean verify(AgentConfirmation approved) {
        String authorization = approved.authorizationId();
        if (authorization == null || !authorization.startsWith(PREFIX)) {
            return fallback.verify(approved);
        }
        OAuth2Authorization recorded = authorizations.findById(authorization.substring(PREFIX.length()));
        if (recorded == null || !AGENT_CONFIRMATION.equals(recorded.getAuthorizationGrantType())) {
            return false;
        }
        Map<String, Object> facts = recorded.getAttributes();
        return approved.confirmationId().equals(facts.get(CONFIRMATION_ID))
                && approved.requestHash().equals(facts.get(REQUEST_HASH))
                && approved.agentId().equals(facts.get(AGENT_ID))
                && approved.userId().equals(facts.get(SUBJECT))
                && Objects.equals(approved.decidedBy(), recorded.getPrincipalName())
                && facts.get(USED_AT) == null;
    }

    @Override
    public void consumed(AgentConfirmation used) {
        String authorization = used.authorizationId();
        if (authorization == null || !authorization.startsWith(PREFIX)) {
            fallback.consumed(used);
            return;
        }
        OAuth2Authorization recorded = authorizations.findById(authorization.substring(PREFIX.length()));
        if (recorded != null) {
            authorizations.save(OAuth2Authorization.from(recorded)
                    .attribute(USED_AT, String.valueOf(used.usedAt() != null ? used.usedAt() : Instant.now()))
                    .build());
        }
    }

    /** The agent's client as this server registers it, or null. */
    @Nullable
    private RegisteredClient agentClient(AgentConfirmation approved) {
        if (registry == null) {
            return null;
        }
        try {
            String clientId = AgentRegistrations.find(registry, approved.tenantId(), approved.agentId())
                    .map(AgentRegistration::clientId).filter(StringUtils::hasText).orElse(null);
            return clientId != null ? clients.findByClientId(clientId) : null;
        } catch (RuntimeException e) {
            log.error("The agent's client could not be read: agentId={}", approved.agentId(), e);
            return null;
        }
    }
}
