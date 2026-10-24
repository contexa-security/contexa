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
package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.resolver.TokenDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A1-1 (docs/agent/Agent보안-구현계획.md): the delegation stamp an access token states, in each token form an agent
 * arrives with (AG-11a): RFC 8693 {@code act}, the agent as {@code client_id}/{@code azp} with the user as {@code sub}
 * (IETF WIMSE AIMS, Microsoft Entra Agent ID), RFC 9396 {@code authorization_details} and snake_case delegation claims.
 * A token that names no agent leaves the stamp to the other resolvers, as before.
 */
class TokenDelegationStampResolverTest {

    private static final Instant ISSUED = Instant.parse("2026-10-21T09:00:00Z");
    private static final Instant EXPIRES = Instant.parse("2026-10-21T10:00:00Z");

    private final TokenDelegationStampResolver resolver = new TokenDelegationStampResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void rfc8693ActorTokenIsADelegationToTheCurrentActorWithPriorActorsAsInformationOnly() {
        authenticate(jwt(Map.of(
                "sub", "user-1",
                "azp", "agent-client",
                "scope", "reports.read reports.export",
                "act", Map.of("sub", "agent-7", "client_id", "agent-client",
                        "act", Map.of("sub", "orchestrator-2")),
                "may_act", Map.of("sub", "agent-7"))));

        DelegationStamp stamp = resolve().orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.subjectId()).isEqualTo("user-1");
        assertThat(stamp.agentId()).isEqualTo("agent-7");
        // A token's expiry bounds what was delegated through it when no delegation expiry is stated.
        assertThat(stamp.expiresAt()).isEqualTo(EXPIRES);
        assertThat(stamp.allowedOperations()).isEmpty();
        assertThat(stamp.attributes())
                .containsEntry("delegationResolver", "TOKEN")
                .containsEntry("delegationTokenForm", TokenDelegationStampResolver.FORM_ACTOR_CLAIM)
                .containsEntry("delegationEvidenceState", BridgeSemanticBoundaryPolicy.SIGNED_TOKEN_CLAIM)
                .containsEntry("delegationChainDepth", 2)
                .containsEntry("delegationPriorActors", List.of("orchestrator-2"))
                .containsEntry("delegationMayAct", List.of("agent-7"))
                .containsEntry("actorClientId", "agent-client")
                .containsEntry("tokenClientId", "agent-client")
                .containsEntry("tokenScopes", List.of("reports.read", "reports.export"))
                .containsEntry("delegationExpiresAtSource", TokenDelegationStampResolver.EXPIRY_FROM_TOKEN);
    }

    @Test
    void entraAgentIdentityActingForAUserIsADelegationToTheAuthorizedParty() {
        authenticate(jwt(Map.of(
                "sub", "user-oid-1",
                "azp", "agent-app-1",
                "idtyp", "user",
                "xms_act_fct", "3 11",
                "scp", "Files.Read")));

        DelegationStamp stamp = resolve().orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.subjectId()).isEqualTo("user-oid-1");
        assertThat(stamp.agentId()).isEqualTo("agent-app-1");
        assertThat(stamp.attributes())
                .containsEntry("delegationTokenForm", TokenDelegationStampResolver.FORM_AGENT_CLIENT)
                .containsEntry("delegationSubjectType", "user")
                .containsEntry("delegationChainDepth", 1)
                .containsEntry("tokenScopes", List.of("Files.Read"));
    }

    @Test
    void entraAgentIdentityActingOnItsOwnIsAStandaloneAgent() {
        authenticate(jwt(Map.of(
                "sub", "agent-sp-1",
                "azp", "agent-app-1",
                "idtyp", "app",
                "xms_act_fct", List.of("11"))));

        DelegationStamp stamp = resolve().orElseThrow();

        assertThat(stamp.delegated()).isFalse();
        assertThat(stamp.agentId()).isEqualTo("agent-app-1");
        assertThat(stamp.subjectId()).isEqualTo("agent-sp-1");
        // A standalone agent has no delegation to expire; the token's own expiry is kept apart.
        assertThat(stamp.expiresAt()).isNull();
        assertThat(stamp.attributes())
                .containsEntry("delegationSubjectType", "app")
                .containsEntry("delegationChainDepth", 0)
                .containsEntry("tokenExpiresAt", EXPIRES.toString());
    }

    @Test
    void snakeCaseDelegationClaimsFillTheDelegatedObjectiveAndScope() {
        authenticate(jwt(Map.ofEntries(
                Map.entry("sub", "tenant-acme-runtime"),
                Map.entry("client_id", "tenant-acme-runtime"),
                Map.entry("execution_mode", "DELEGATED_AGENT"),
                Map.entry("agent_id", "soar-agent-3"),
                Map.entry("objective_id", "obj-77"),
                Map.entry("objective_family", "INCIDENT_RESPONSE"),
                Map.entry("task_purpose", "Contain the reported incident"),
                Map.entry("allowed_operations", List.of("READ", "CONTAIN")),
                Map.entry("allowed_resource_families", List.of("INCIDENT")),
                Map.entry("containment_only", true),
                Map.entry("privileged_export_allowed", false),
                Map.entry("execution_expires_at", "2026-10-21T09:30:00Z"))));

        DelegationStamp stamp = resolve().orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("soar-agent-3");
        assertThat(stamp.objectiveId()).isEqualTo("obj-77");
        assertThat(stamp.objectiveFamily()).isEqualTo("INCIDENT_RESPONSE");
        assertThat(stamp.objectiveSummary()).isEqualTo("Contain the reported incident");
        assertThat(stamp.allowedOperations()).containsExactly("READ", "CONTAIN");
        assertThat(stamp.allowedResources()).containsExactly("INCIDENT");
        assertThat(stamp.containmentOnly()).isTrue();
        assertThat(stamp.privilegedExportAllowed()).isFalse();
        assertThat(stamp.expiresAt()).isEqualTo(Instant.parse("2026-10-21T09:30:00Z"));
        assertThat(stamp.attributes())
                .containsEntry("delegationTokenForm", TokenDelegationStampResolver.FORM_DELEGATION_CLAIMS)
                .containsEntry("delegationExpiresAtSource", TokenDelegationStampResolver.EXPIRY_FROM_DELEGATION_CLAIM);
    }

    @Test
    void rfc9396AuthorizationDetailsAreTheDelegatedOperationsAndResources() {
        authenticate(jwt(Map.of(
                "sub", "user-1",
                "act", Map.of("sub", "agent-7"),
                "authorization_details", List.of(
                        Map.of("type", "report_export",
                                "actions", List.of("read", "export"),
                                "locations", List.of("https://api.example.com/projects/HX-310"),
                                "identifier", "HX-310"),
                        Map.of("type", "customer_lookup",
                                "actions", List.of("read"),
                                "datatypes", List.of("contact"))))));

        DelegationStamp stamp = resolve().orElseThrow();

        assertThat(stamp.allowedOperations()).containsExactly("read", "export");
        assertThat(stamp.allowedResources())
                .containsExactly("https://api.example.com/projects/HX-310", "HX-310", "contact");
        assertThat(stamp.attributes())
                .containsEntry("authorizationDetailTypes", List.of("report_export", "customer_lookup"));
    }

    @Test
    void aPersonsTokenThatNamesNoAgentLeavesTheStampToTheOtherResolvers() {
        authenticate(jwt(Map.of(
                "sub", "user-1",
                "azp", "web-app",
                "scope", "profile reports.read")));

        assertThat(resolve()).isEmpty();
    }

    @Test
    void aClientTheHostListsAsAnAgentIsReadInTheAimsForm() {
        BridgeProperties properties = new BridgeProperties();
        properties.getDelegation().getToken().setAgentClientIds(List.of("report-agent"));
        authenticate(jwt(Map.of("sub", "user-1", "client_id", "report-agent")));

        DelegationStamp stamp = resolver.resolve(null, null, properties).orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("report-agent");
        assertThat(stamp.subjectId()).isEqualTo("user-1");
        assertThat(stamp.attributes()).containsEntry("delegationTokenForm", TokenDelegationStampResolver.FORM_AGENT_CLIENT);
    }

    @Test
    void aRegisteredAgentClientsOwnTokenIsAStandaloneAgentUnderItsRegisteredId() {
        List<String> lookups = new ArrayList<>();
        TokenDelegationStampResolver withDirectory = new TokenDelegationStampResolver((tenantId, clientId) -> {
            lookups.add(tenantId + "|" + clientId);
            return "report-bot-client".equals(clientId) ? Optional.of("report-bot") : Optional.empty();
        });
        authenticate(jwt(Map.of("sub", "report-bot-client", "client_id", "report-bot-client")));

        DelegationStamp stamp = withDirectory.resolve(null, null, new BridgeProperties()).orElseThrow();

        assertThat(stamp.delegated()).isFalse();
        assertThat(stamp.agentId()).isEqualTo("report-bot");
        assertThat(stamp.subjectId()).isEqualTo("report-bot-client");
        assertThat(stamp.attributes()).containsEntry("delegationTokenForm", TokenDelegationStampResolver.FORM_AGENT_CLIENT);
        assertThat(lookups).containsExactly("null|report-bot-client");
    }

    @Test
    void aRegisteredAgentClientActingForAPersonIsADelegationToThatAgent() {
        TokenDelegationStampResolver withDirectory = new TokenDelegationStampResolver((tenantId, clientId) ->
                "report-bot-client".equals(clientId) ? Optional.of("report-bot") : Optional.empty());
        authenticate(jwt(Map.of("sub", "user-1", "client_id", "report-bot-client", "tid", "acme")));

        DelegationStamp stamp = withDirectory.resolve(null, null, new BridgeProperties()).orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("report-bot");
        assertThat(stamp.subjectId()).isEqualTo("user-1");
    }

    @Test
    void anExchangedTokenWhoseActorIsARegisteredAgentClientNamesTheRegisteredAgent() {
        // Spring Authorization Server token exchange: sub is the person, act holds the actor token's iss and sub.
        TokenDelegationStampResolver withDirectory = new TokenDelegationStampResolver((tenantId, clientId) ->
                "report-bot-client".equals(clientId) ? Optional.of("report-bot") : Optional.empty());
        authenticate(jwt(Map.of("sub", "user-1", "client_id", "report-bot-client",
                "act", Map.of("iss", "https://contexa.example", "sub", "report-bot-client"))));

        DelegationStamp stamp = withDirectory.resolve(null, null, new BridgeProperties()).orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("report-bot");
        assertThat(stamp.subjectId()).isEqualTo("user-1");
        assertThat(stamp.attributes()).containsEntry("delegationTokenForm", TokenDelegationStampResolver.FORM_ACTOR_CLAIM);
    }

    @Test
    void theDelegationIdClaimIsRecordedAsTheDelegationId() {
        authenticate(jwt(Map.of("sub", "user-1", "act", Map.of("sub", "agent-x"), "delegation_id", "dlg-7")));

        assertThat(resolve().orElseThrow().attributes()).containsEntry("delegationId", "dlg-7");
    }

    @Test
    void anActorTheDirectoryDoesNotNameKeepsItsOwnIdentifier() {
        TokenDelegationStampResolver withDirectory = new TokenDelegationStampResolver((tenantId, clientId) -> Optional.empty());
        authenticate(jwt(Map.of("sub", "user-1", "act", Map.of("sub", "external-agent"))));

        assertThat(withDirectory.resolve(null, null, new BridgeProperties()).orElseThrow().agentId())
                .isEqualTo("external-agent");
    }

    @Test
    void theTenantClaimScopesTheRegisteredAgentLookup() {
        List<String> lookups = new ArrayList<>();
        TokenDelegationStampResolver withDirectory = new TokenDelegationStampResolver((tenantId, clientId) -> {
            lookups.add(tenantId + "|" + clientId);
            return Optional.empty();
        });
        authenticate(jwt(Map.of("sub", "svc", "client_id", "svc", "tenant_id", "acme")));

        assertThat(withDirectory.resolve(null, null, new BridgeProperties())).isEmpty();
        assertThat(lookups).containsExactly("acme|svc");
    }

    @Test
    void aClientNoDirectoryOrSettingNamesIsNotAnAgent() {
        TokenDelegationStampResolver withDirectory = new TokenDelegationStampResolver((tenantId, clientId) -> Optional.empty());
        authenticate(jwt(Map.of("sub", "default-client", "client_id", "default-client")));

        assertThat(withDirectory.resolve(null, null, new BridgeProperties())).isEmpty();
    }

    @Test
    void claimNamesAreSettings() {
        BridgeProperties properties = bind(Map.of(
                "contexa.bridge.delegation.token.actor-claims", "actor",
                "contexa.bridge.delegation.token.agent-actor-markers.agent_kind[0]", "ai"));
        authenticate(jwt(Map.of("sub", "user-1", "actor", Map.of("sub", "agent-9"))));

        DelegationStamp stamp = resolver.resolve(null, null, properties).orElseThrow();

        assertThat(stamp.agentId()).isEqualTo("agent-9");
        assertThat(properties.getDelegation().getToken().getAgentActorMarkers())
                .containsEntry("agent_kind", List.of("ai"));

        authenticate(jwt(Map.of("sub", "user-2", "azp", "worker", "agent_kind", "ai")));
        assertThat(resolver.resolve(null, null, properties).orElseThrow().agentId()).isEqualTo("worker");
    }

    @Test
    void theTokenChannelCanBeTurnedOff() {
        BridgeProperties properties = new BridgeProperties();
        properties.getDelegation().getToken().setEnabled(false);
        authenticate(jwt(Map.of("sub", "user-1", "act", Map.of("sub", "agent-7"))));

        assertThat(resolver.resolve(null, null, properties)).isEmpty();
    }

    @Test
    void anOpenIdConnectLoginIsAPersonNotAnAgentToken() {
        DefaultOAuth2User user = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("sub", "user-1", "act", Map.of("sub", "agent-7")),
                "sub");
        SecurityContextHolder.getContext().setAuthentication(
                new OAuth2AuthenticationToken(user, user.getAuthorities(), "google"));

        assertThat(resolve()).isEmpty();
    }

    @Test
    void aHostResourceServerThatIntrospectsAnOpaqueTokenIsReadTheSameWay() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("sub", "user-1");
        attributes.put("client_id", "agent-client");
        attributes.put("act", Map.of("sub", "agent-7"));
        attributes.put("exp", EXPIRES);
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(
                "user-1", attributes, List.of(new SimpleGrantedAuthority("SCOPE_reports.read")));
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque", ISSUED, EXPIRES);
        SecurityContextHolder.getContext().setAuthentication(
                new BearerTokenAuthentication(principal, token, principal.getAuthorities()));

        DelegationStamp stamp = resolve().orElseThrow();

        assertThat(stamp.delegated()).isTrue();
        assertThat(stamp.agentId()).isEqualTo("agent-7");
        assertThat(stamp.subjectId()).isEqualTo("user-1");
        assertThat(stamp.expiresAt()).isEqualTo(EXPIRES);
    }

    private Optional<DelegationStamp> resolve() {
        return resolver.resolve(null, null, new BridgeProperties());
    }

    private static void authenticate(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("header.payload.signature")
                .header("alg", "RS256")
                .issuedAt(ISSUED)
                .expiresAt(EXPIRES);
        claims.forEach(builder::claim);
        return builder.build();
    }

    private static BridgeProperties bind(Map<String, String> values) {
        return new Binder(new MapConfigurationPropertySource(values))
                .bind("contexa.bridge", BridgeProperties.class)
                .orElseGet(BridgeProperties::new);
    }
}
