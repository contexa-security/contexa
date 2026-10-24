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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What an access token says about how its request was authorised (A2-11, AG-12f), read from the token itself: the kind
 * of credential, the grant its form shows (RFC 8693 {@code act}: a token exchange; a client's own token: client
 * credentials; otherwise only a grant the token states), the client it was issued to, when it was issued and until
 * when it holds, the actors before the one sending it, and whether it is bound to a key (RFC 9449 DPoP {@code cnf.jkt},
 * RFC 8705 {@code cnf.x5t#S256}). A request authenticated by a session carries none: its facts are the session's.
 *
 * @param kind        {@link #USER_TOKEN}, {@link #DELEGATED_TOKEN} or {@link #CLIENT_TOKEN}
 * @param grant       the grant the token shows or states; null when it shows none
 * @param chainDepth  the number of actors in the token's actor chain (0 without one)
 * @param priorActors the actors before the one sending the token, nearest first
 * @param binding     {@link #BINDING_DPOP}, {@link #BINDING_MTLS} or null for a bearer token
 * @param checkedAt   when the resource server read the token, on its own clock: the token's times are on the issuer's
 *                    clock, which the request time a host states (its observed time) need not share
 */
public record CredentialFacts(String kind, @Nullable String grant, @Nullable String clientId,
                              @Nullable Instant issuedAt, @Nullable Instant expiresAt, int chainDepth,
                              List<String> priorActors, @Nullable String binding, @Nullable Instant checkedAt) {

    public static final String USER_TOKEN = "USER_TOKEN";
    public static final String DELEGATED_TOKEN = "DELEGATED_TOKEN";
    public static final String CLIENT_TOKEN = "CLIENT_TOKEN";
    public static final String GRANT_TOKEN_EXCHANGE = "token-exchange";
    public static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    public static final String BINDING_DPOP = "DPoP";
    public static final String BINDING_MTLS = "mTLS certificate";

    /** The payload keys the facts travel under to the decision (event metadata, then the canonical context). */
    public static final String KIND = "credentialKind";
    public static final String GRANT = "credentialGrant";
    public static final String CLIENT_ID = "credentialClientId";
    public static final String ISSUED_AT = "credentialIssuedAt";
    public static final String EXPIRES_AT = "credentialExpiresAt";
    public static final String CHAIN_DEPTH = "credentialChainDepth";
    public static final String PRIOR_ACTORS = "credentialPriorActors";
    public static final String BINDING = "credentialBinding";
    public static final String CHECKED_AT = "credentialCheckedAt";

    /** The claims a token may state its grant in (Auth0 {@code gty}, a plain {@code grant_type}). */
    private static final List<String> GRANT_CLAIMS = List.of("gty", "grant_type");
    private static final int MAX_ACTOR_DEPTH = 10;

    public CredentialFacts {
        priorActors = priorActors == null ? List.of() : List.copyOf(priorActors);
    }

    /** The facts of the access token behind an authentication, read now; empty for any other authentication. */
    public static Optional<CredentialFacts> of(@Nullable Authentication authentication,
                                               @Nullable BridgeProperties.Delegation.Token config) {
        return of(authentication, config, Instant.now());
    }

    /** The facts of the access token behind an authentication, read at the given time; empty for any other one. */
    public static Optional<CredentialFacts> of(@Nullable Authentication authentication,
                                               @Nullable BridgeProperties.Delegation.Token config,
                                               @Nullable Instant checkedAt) {
        Map<String, Object> claims = OAuth2AuthenticationSupport.tokenClaims(authentication);
        if (claims.isEmpty()) {
            return Optional.empty();
        }
        BridgeProperties.Delegation.Token token = config != null ? config : new BridgeProperties.Delegation.Token();
        Map<String, Object> actor = AgentTokenClaims.firstMap(claims, token.getActorClaims());
        int depth = 0;
        List<String> priorActors = new ArrayList<>();
        if (actor != null) {
            depth = 1;
            Map<String, Object> prior = AgentTokenClaims.firstMap(actor, token.getActorClaims());
            while (prior != null && depth < MAX_ACTOR_DEPTH) {
                String priorActor = AgentTokenClaims.firstNonBlank(AgentTokenClaims.text(prior.get("sub")),
                        AgentTokenClaims.text(prior.get("client_id")));
                if (priorActor != null) {
                    priorActors.add(priorActor);
                }
                depth++;
                prior = AgentTokenClaims.firstMap(prior, token.getActorClaims());
            }
        }
        String grant = AgentTokenClaims.firstText(claims, GRANT_CLAIMS);
        String kind;
        if (actor != null) {
            kind = DELEGATED_TOKEN;
            grant = grant != null ? grant : GRANT_TOKEN_EXCHANGE;
        } else if (AgentTokenClaims.isClientOwnToken(claims, token)) {
            kind = CLIENT_TOKEN;
            grant = grant != null ? grant : GRANT_CLIENT_CREDENTIALS;
        } else {
            kind = USER_TOKEN;
        }
        return Optional.of(new CredentialFacts(kind, grant, AgentTokenClaims.firstText(claims, token.getClientIdClaims()),
                instant(claims.get("iat")), instant(claims.get("exp")), depth, priorActors, binding(claims),
                checkedAt));
    }

    /** The facts under their payload keys; a fact the token does not state is left out. */
    public Map<String, Object> payload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put(KIND, kind);
        put(payload, GRANT, grant);
        put(payload, CLIENT_ID, clientId);
        put(payload, ISSUED_AT, issuedAt != null ? issuedAt.toString() : null);
        put(payload, EXPIRES_AT, expiresAt != null ? expiresAt.toString() : null);
        payload.put(CHAIN_DEPTH, chainDepth);
        if (!priorActors.isEmpty()) {
            payload.put(PRIOR_ACTORS, priorActors);
        }
        put(payload, BINDING, binding);
        put(payload, CHECKED_AT, checkedAt != null ? checkedAt.toString() : null);
        return payload;
    }

    @Nullable
    private static String binding(Map<String, Object> claims) {
        if (!(claims.get("cnf") instanceof Map<?, ?> confirmation)) {
            return null;
        }
        if (confirmation.get("jkt") != null) {
            return BINDING_DPOP;
        }
        if (confirmation.get("x5t#S256") != null) {
            return BINDING_MTLS;
        }
        return null;
    }

    @Nullable
    private static Instant instant(@Nullable Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Date date) {
            return date.toInstant();
        }
        if (value instanceof Number seconds) {
            return Instant.ofEpochSecond(seconds.longValue());
        }
        if (value != null) {
            try {
                return Instant.parse(value.toString().trim());
            } catch (RuntimeException notAnInstant) {
                return null;
            }
        }
        return null;
    }

    private static void put(Map<String, Object> payload, String key, @Nullable String value) {
        if (value != null && !value.isBlank()) {
            payload.put(key, value);
        }
    }
}
