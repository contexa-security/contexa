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
package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.domain.TruthValues;
import io.contexa.contexacommon.security.bridge.AgentTokenClaims;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The delegation an OAuth2 access token states (A1-1, AG-11a), read from the authentication of the request, so it
 * works the same whether Contexa's chain or the host's resource server validated the token. The token forms are those
 * of {@link AgentTokenClaims}; prior actors of an RFC 8693 chain are kept as facts and never as grounds for access.
 *
 * <p>RFC 9396 {@code authorization_details} add their actions to the delegated operations and their locations,
 * data types and identifiers to the delegated resources. A token that names no agent yields no stamp, so the session,
 * request attribute and header channels decide as before. Every claim name is a setting
 * ({@code contexa.bridge.delegation.token.*}).
 */
public class TokenDelegationStampResolver implements DelegationStampResolver {

    public static final String FORM_ACTOR_CLAIM = AgentTokenClaims.FORM_ACTOR_CLAIM;
    public static final String FORM_DELEGATION_CLAIMS = AgentTokenClaims.FORM_DELEGATION_CLAIMS;
    public static final String FORM_AGENT_CLIENT = AgentTokenClaims.FORM_AGENT_CLIENT;
    public static final String EXPIRY_FROM_DELEGATION_CLAIM = "DELEGATION_CLAIM";
    public static final String EXPIRY_FROM_TOKEN = "TOKEN_EXPIRY";

    /** The deepest actor nesting read; a deeper chain is cut there, so a crafted token cannot make reading unbounded. */
    static final int MAX_ACTOR_DEPTH = 10;

    @Override
    public Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext,
                                             BridgeProperties properties) {
        BridgeProperties.Delegation.Token config = config(properties);
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> claims = OAuth2AuthenticationSupport.tokenClaims(authentication);
        if (claims.isEmpty()) {
            return Optional.empty();
        }
        Optional<AgentTokenClaims.Agent> named = AgentTokenClaims.agent(claims,
                authentication != null ? authentication.getName() : null, config);
        if (named.isEmpty()) {
            return Optional.empty();
        }
        AgentTokenClaims.Agent agent = named.get();

        String actorClientId = null;
        List<String> priorActors = new ArrayList<>();
        int depth;
        if (agent.actor() != null) {
            actorClientId = AgentTokenClaims.text(agent.actor().get("client_id"));
            depth = 1;
            Map<String, Object> prior = AgentTokenClaims.firstMap(agent.actor(), config.getActorClaims());
            while (prior != null && depth < MAX_ACTOR_DEPTH) {
                String priorActor = AgentTokenClaims.firstNonBlank(AgentTokenClaims.text(prior.get("sub")),
                        AgentTokenClaims.text(prior.get("client_id")));
                if (priorActor != null) {
                    priorActors.add(priorActor);
                }
                depth++;
                prior = AgentTokenClaims.firstMap(prior, config.getActorClaims());
            }
        } else {
            depth = agent.delegated() ? 1 : 0;
        }

        LinkedHashSet<String> operations = new LinkedHashSet<>(firstStrings(claims, config.getAllowedOperationsClaims()));
        LinkedHashSet<String> resources = new LinkedHashSet<>(firstStrings(claims, config.getAllowedResourcesClaims()));
        List<String> detailTypes = new ArrayList<>();
        readAuthorizationDetails(claims, config, operations, resources, detailTypes);

        Instant delegationExpiry = firstInstant(claims, config.getExpiresAtClaims());
        Instant tokenExpiry = instant(claims.get("exp"));
        Instant expiresAt = delegationExpiry != null ? delegationExpiry : (agent.delegated() ? tokenExpiry : null);

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", "TOKEN");
        attributes.put("delegationTokenForm", agent.form());
        attributes.put("delegationEvidenceState", BridgeSemanticBoundaryPolicy.SIGNED_TOKEN_CLAIM);
        attributes.put("delegationChainDepth", depth);
        if (!priorActors.isEmpty()) {
            attributes.put("delegationPriorActors", List.copyOf(priorActors));
        }
        List<String> mayAct = mayActParties(claims, config);
        if (!mayAct.isEmpty()) {
            attributes.put("delegationMayAct", mayAct);
        }
        putIfPresent(attributes, "actorClientId", actorClientId);
        putIfPresent(attributes, "tokenClientId", agent.clientId());
        List<String> scopes = scopes(claims, config);
        if (!scopes.isEmpty()) {
            attributes.put("tokenScopes", scopes);
        }
        putIfPresent(attributes, "tokenIssuer", AgentTokenClaims.text(claims.get("iss")));
        putIfPresent(attributes, "delegationSubjectType", agent.subjectType());
        if (delegationExpiry != null) {
            attributes.put("delegationExpiresAtSource", EXPIRY_FROM_DELEGATION_CLAIM);
        } else if (expiresAt != null) {
            attributes.put("delegationExpiresAtSource", EXPIRY_FROM_TOKEN);
        }
        if (tokenExpiry != null) {
            attributes.put("tokenExpiresAt", tokenExpiry.toString());
        }
        if (!detailTypes.isEmpty()) {
            attributes.put("authorizationDetailTypes", List.copyOf(detailTypes));
        }

        return Optional.of(new DelegationStamp(
                agent.subject(),
                agent.agentId(),
                agent.delegated(),
                AgentTokenClaims.firstText(claims, config.getObjectiveIdClaims()),
                AgentTokenClaims.firstText(claims, config.getObjectiveFamilyClaims()),
                AgentTokenClaims.firstText(claims, config.getObjectiveSummaryClaims()),
                List.copyOf(operations),
                List.copyOf(resources),
                firstBoolean(claims, config.getApprovalRequiredClaims()),
                firstBoolean(claims, config.getPrivilegedExportAllowedClaims()),
                firstBoolean(claims, config.getContainmentOnlyClaims()),
                expiresAt,
                attributes));
    }

    private static BridgeProperties.Delegation.Token config(BridgeProperties properties) {
        if (properties == null || properties.getDelegation() == null || properties.getDelegation().getToken() == null) {
            return new BridgeProperties.Delegation.Token();
        }
        return properties.getDelegation().getToken();
    }

    /** RFC 9396: actions are delegated operations; locations, data types and identifiers are delegated resources. */
    private static void readAuthorizationDetails(Map<String, Object> claims, BridgeProperties.Delegation.Token config,
                                                 Set<String> operations, Set<String> resources, List<String> types) {
        for (String name : config.getAuthorizationDetailsClaims()) {
            Object value = claims.get(name);
            if (!(value instanceof Collection<?> details)) {
                continue;
            }
            for (Object detail : details) {
                if (!(detail instanceof Map<?, ?> entry)) {
                    continue;
                }
                String type = AgentTokenClaims.text(entry.get("type"));
                if (type != null && !types.contains(type)) {
                    types.add(type);
                }
                operations.addAll(AgentTokenClaims.strings(entry.get("actions")));
                resources.addAll(AgentTokenClaims.strings(entry.get("locations")));
                resources.addAll(AgentTokenClaims.strings(entry.get("datatypes")));
                String identifier = AgentTokenClaims.text(entry.get("identifier"));
                if (identifier != null) {
                    resources.add(identifier);
                }
            }
            return;
        }
    }

    /** The parties RFC 8693 {@code may_act} names; an object or a list of objects. Information only. */
    private static List<String> mayActParties(Map<String, Object> claims, BridgeProperties.Delegation.Token config) {
        List<String> parties = new ArrayList<>();
        for (String name : config.getMayActClaims()) {
            Object value = claims.get(name);
            Collection<?> entries = value instanceof Collection<?> collection ? collection
                    : value != null ? List.of(value) : List.of();
            for (Object entry : entries) {
                if (entry instanceof Map<?, ?> party) {
                    String id = AgentTokenClaims.firstNonBlank(AgentTokenClaims.text(party.get("sub")),
                            AgentTokenClaims.text(party.get("client_id")));
                    if (id != null && !parties.contains(id)) {
                        parties.add(id);
                    }
                }
            }
        }
        return List.copyOf(parties);
    }

    private static List<String> scopes(Map<String, Object> claims, BridgeProperties.Delegation.Token config) {
        LinkedHashSet<String> scopes = new LinkedHashSet<>();
        for (String name : config.getScopeClaims()) {
            scopes.addAll(AgentTokenClaims.strings(claims.get(name)));
        }
        return List.copyOf(scopes);
    }

    private static List<String> firstStrings(Map<String, Object> claims, List<String> names) {
        for (String name : names) {
            List<String> values = AgentTokenClaims.strings(claims.get(name));
            if (!values.isEmpty()) {
                return values;
            }
        }
        return List.of();
    }

    private static Boolean firstBoolean(Map<String, Object> claims, List<String> names) {
        for (String name : names) {
            Boolean value = TruthValues.parse(claims.get(name));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static Instant firstInstant(Map<String, Object> claims, List<String> names) {
        for (String name : names) {
            Instant value = instant(claims.get(name));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    /** An instant claim: an instant, seconds since the epoch (JWT NumericDate) or ISO-8601 text. */
    private static Instant instant(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        String text = AgentTokenClaims.text(value);
        if (text == null) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException ignored) {
            try {
                return Instant.ofEpochSecond(Long.parseLong(text));
            } catch (NumberFormatException notANumber) {
                return null;
            }
        }
    }

    private static void putIfPresent(Map<String, Object> attributes, String key, String value) {
        if (value != null) {
            attributes.put(key, value);
        }
    }
}
