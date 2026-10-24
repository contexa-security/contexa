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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

/**
 * The session an agent's or a client's token request belongs to (A1-11, AG-12c). A person's request keeps the session
 * of its login; an agent has no login of its own, so its requests are grouped by the login session its token carries
 * ({@code sid}), else the delegation it states, else the token itself ({@code jti}), always within that agent, so two
 * agents (or an agent and the person it acts for) never share a session. The session narrative, the context binding
 * hash, the re-entry guard and the decision records all use this key.
 *
 * <p>It reads only the token's claims, so every filter of a request computes the same key, also those that run before
 * the bridge resolves the delegation. An agent signed in with its own account (a session login) keeps its HTTP session.
 * Claim names come from {@code contexa.bridge.delegation.token.*}, registered at startup.</p>
 */
public final class AgentSessionKey {

    public static final String AGENT_PREFIX = "agent";
    public static final String CLIENT_PREFIX = "client";

    private static volatile BridgeProperties.Delegation.Token tokenSettings;

    private AgentSessionKey() {
    }

    /** Uses these claim names; null returns to the defaults. */
    public static void configure(@Nullable BridgeProperties.Delegation.Token settings) {
        tokenSettings = settings;
    }

    /**
     * The session key of the request's token when it is an agent's or a client's own token, or {@code null} for a
     * person's token, a request without a token, or a token naming no login, delegation or token ID.
     */
    @Nullable
    public static String of(@Nullable Authentication authentication) {
        Map<String, Object> claims = OAuth2AuthenticationSupport.tokenClaims(authentication);
        if (claims.isEmpty()) {
            return null;
        }
        BridgeProperties.Delegation.Token config = settings();
        String party;
        String prefix;
        AgentTokenClaims.Agent agent = AgentTokenClaims.agent(claims,
                authentication != null ? authentication.getName() : null, config).orElse(null);
        if (agent != null && agent.agentId() != null) {
            party = agent.agentId();
            prefix = AGENT_PREFIX;
        } else if (AgentTokenClaims.isClientOwnToken(claims, config)) {
            party = AgentTokenClaims.text(claims.get("sub"));
            prefix = CLIENT_PREFIX;
        } else {
            return null;
        }
        String basis;
        String kind;
        String sid = AgentTokenClaims.text(claims.get(OAuth2AuthenticationSupport.SESSION_ID_CLAIM));
        String delegationId = AgentTokenClaims.firstText(claims, config.getDelegationIdClaims());
        String tokenId = AgentTokenClaims.text(claims.get("jti"));
        if (sid != null) {
            kind = "sid";
            basis = sid;
        } else if (delegationId != null) {
            kind = "delegation";
            basis = delegationId;
        } else if (tokenId != null) {
            kind = "jti";
            basis = tokenId;
        } else {
            return null;
        }
        return prefix + ":" + kind + ":" + digest(party + "|" + basis);
    }

    private static BridgeProperties.Delegation.Token settings() {
        BridgeProperties.Delegation.Token configured = tokenSettings;
        return configured != null ? configured : new BridgeProperties.Delegation.Token();
    }

    /** A short digest, so raw login and token identifiers are not written into store keys. */
    private static String digest(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 16);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is not available", impossible);
        }
    }
}
