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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What an access token's claims say about an agent (A1-1, A1-2, AG-11a): one reading shared by the delegation stamp
 * resolver and the resource server's token converter, so both recognise the same tokens.
 *
 * <p>Token forms, in the order they are recognised:
 * <ol>
 *     <li>{@link #FORM_ACTOR_CLAIM}: an RFC 8693 actor claim; the outermost actor is the agent acting now and the
 *     subject is the party it acts for.</li>
 *     <li>{@link #FORM_DELEGATION_CLAIMS}: an agent ID claim or a delegation marker claim.</li>
 *     <li>{@link #FORM_AGENT_CLIENT}: the agent as the client the token was issued to and the user as the subject
 *     (IETF WIMSE AIMS, Microsoft Entra Agent ID), recognised by an agent marker claim, a client ID the settings list as
 *     an agent, or a client the {@link AgentClientDirectory} names as an approved agent. The subject type claim tells
 *     an agent acting for a person from one acting on its own.</li>
 * </ol>
 * Every claim name comes from {@link BridgeProperties.Delegation.Token}.
 */
public final class AgentTokenClaims {

    public static final String FORM_ACTOR_CLAIM = "ACTOR_CLAIM";
    public static final String FORM_DELEGATION_CLAIMS = "DELEGATION_CLAIMS";
    public static final String FORM_AGENT_CLIENT = "AGENT_CLIENT";

    private AgentTokenClaims() {
    }

    /**
     * The agent a token names.
     *
     * @param form        the token form it was recognised in
     * @param subject     the token's subject: the delegating party when {@code delegated}, else the agent itself
     * @param agentId     the agent acting now
     * @param delegated   whether the agent acts for another party
     * @param clientId    the client the token was issued to, when the token names it
     * @param subjectType the subject type the token states ({@code user}, {@code app}), when it states one
     * @param actor       the outermost actor claim, when the token has one
     */
    public record Agent(String form, String subject, String agentId, boolean delegated, String clientId,
                        String subjectType, Map<String, Object> actor) {
    }

    /** The agent the claims name; empty for a token that names no agent (a person's token, a plain client token). */
    public static Optional<Agent> agent(Map<String, Object> claims, String fallbackSubject,
                                        BridgeProperties.Delegation.Token config) {
        return agent(claims, fallbackSubject, config, AgentClientDirectory.NONE);
    }

    /**
     * The agent the claims name, also recognising a client the directory names as an approved agent; that agent is
     * named by its registered identifier, also when it is the actor of an exchanged token.
     */
    public static Optional<Agent> agent(Map<String, Object> claims, String fallbackSubject,
                                        BridgeProperties.Delegation.Token config, AgentClientDirectory directory) {
        if (claims == null || claims.isEmpty() || config == null) {
            return Optional.empty();
        }
        Map<String, Object> actor = firstMap(claims, config.getActorClaims());
        String clientId = firstText(claims, config.getClientIdClaims());
        String agentIdClaim = firstText(claims, config.getAgentIdClaims());
        String registeredAgentId = registeredAgent(claims, clientId, config, directory);
        boolean delegatedMarked = matchesMarker(claims, config.getDelegatedMarkers());
        boolean agentMarked = matchesMarker(claims, config.getAgentActorMarkers())
                || (clientId != null && config.getAgentClientIds() != null && config.getAgentClientIds().contains(clientId))
                || registeredAgentId != null;

        String form;
        if (actor != null) {
            form = FORM_ACTOR_CLAIM;
        } else if (agentIdClaim != null || delegatedMarked) {
            form = FORM_DELEGATION_CLAIMS;
        } else if (agentMarked) {
            form = FORM_AGENT_CLIENT;
        } else {
            return Optional.empty();
        }

        String subject = firstNonBlank(text(claims.get("sub")), fallbackSubject);
        String subjectType = firstText(claims, config.getSubjectTypeClaims());
        String agentId;
        if (actor != null) {
            // The actor of an exchanged token is named by its actor token's subject: for an agent's own token, its
            // client, which an approved agent is registered under (A1-12).
            String actorParty = firstNonBlank(text(actor.get("sub")), text(actor.get("client_id")));
            agentId = firstNonBlank(registeredAgent(claims, actorParty, config, directory), actorParty, agentIdClaim,
                    clientId);
        } else {
            agentId = firstNonBlank(agentIdClaim, registeredAgentId, clientId);
        }

        boolean delegated;
        if (actor != null || delegatedMarked) {
            delegated = true;
        } else if (subjectType != null) {
            delegated = containsIgnoreCase(config.getUserSubjectTypes(), subjectType);
        } else {
            // Without a subject type, an agent acts for someone else when the subject is not the agent itself.
            delegated = subject != null && !subject.equals(agentId) && !subject.equals(clientId);
        }
        return Optional.of(new Agent(form, subject, agentId, delegated, clientId, subjectType, actor));
    }

    /** The tenant the token names, by the configured tenant claims; {@code null} when it names none. */
    public static String tenant(Map<String, Object> claims, BridgeProperties.Delegation.Token config) {
        return config == null ? null : firstText(claims, config.getTenantClaims());
    }

    /**
     * The registered identifier of the approved agent the token's client is, or {@code null}. This reads a token that was
     * already accepted, for the stamp of the request, and refuses nothing: the request must go on, and every request that
     * carries a client reaches this, a person's included. A directory that cannot answer (it says so in its log) leaves the
     * token unnamed here; the places that accept or issue tokens refuse a client they cannot read about.
     */
    static String registeredAgent(Map<String, Object> claims, String clientId,
                                  BridgeProperties.Delegation.Token config, AgentClientDirectory directory) {
        if (clientId == null || directory == null) {
            return null;
        }
        try {
            return directory.requestPathActiveAgentForClient(tenant(claims, config), clientId)
                    .map(AgentTokenClaims::text)
                    .orElse(null);
        } catch (AgentClientStatusUnavailableException unreadable) {
            return null;
        }
    }

    /**
     * Whether the token is a client's own token: its subject is the client it was issued to (client credentials).
     */
    public static boolean isClientOwnToken(Map<String, Object> claims, BridgeProperties.Delegation.Token config) {
        if (claims == null || config == null) {
            return false;
        }
        String subject = text(claims.get("sub"));
        if (subject == null) {
            return false;
        }
        for (String name : config.getClientIdClaims()) {
            if (subject.equals(text(claims.get(name)))) {
                return true;
            }
        }
        return false;
    }

    /** The first non-empty object claim among the names. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> firstMap(Map<String, Object> claims, List<String> names) {
        if (claims == null || names == null) {
            return null;
        }
        for (String name : names) {
            if (claims.get(name) instanceof Map<?, ?> map && !map.isEmpty()) {
                return (Map<String, Object>) map;
            }
        }
        return null;
    }

    /** The first text claim among the names; a list or object claim is passed over. */
    public static String firstText(Map<String, Object> claims, List<String> names) {
        if (claims == null || names == null) {
            return null;
        }
        for (String name : names) {
            Object value = claims.get(name);
            if (value instanceof Collection<?> || value instanceof Map<?, ?>) {
                continue;
            }
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    /** A list claim, or a text claim of values separated by spaces (OAuth {@code scope}, Entra {@code xms_act_fct}). */
    public static List<String> strings(Object value) {
        List<String> values = new ArrayList<>();
        if (value instanceof Collection<?> collection) {
            for (Object element : collection) {
                String text = text(element);
                if (text != null) {
                    values.add(text);
                }
            }
        } else if (value instanceof Number number) {
            values.add(number.toString());
        } else {
            String text = text(value);
            if (text != null) {
                for (String part : text.split("\\s+")) {
                    if (!part.isBlank()) {
                        values.add(part);
                    }
                }
            }
        }
        return values;
    }

    /** Whether any marker claim holds one of its listed values; a value may hold several, separated by spaces. */
    static boolean matchesMarker(Map<String, Object> claims, Map<String, List<String>> markers) {
        if (markers == null) {
            return false;
        }
        for (Map.Entry<String, List<String>> marker : markers.entrySet()) {
            for (String value : strings(claims.get(marker.getKey()))) {
                if (containsIgnoreCase(marker.getValue(), value)) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean containsIgnoreCase(List<String> values, String candidate) {
        if (values == null || candidate == null) {
            return false;
        }
        for (String value : values) {
            if (value != null && value.trim().equalsIgnoreCase(candidate.trim())) {
                return true;
            }
        }
        return false;
    }

    /** The first value that is not blank, trimmed. */
    public static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    /** A claim as trimmed text; null for no value or a blank one. */
    public static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
