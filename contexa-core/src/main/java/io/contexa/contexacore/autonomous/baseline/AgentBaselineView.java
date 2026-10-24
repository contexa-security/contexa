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
package io.contexa.contexacore.autonomous.baseline;

import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What an agent usually does that a person's baseline has no dimension for (docs/agent A4-1, A4-6): the order of its
 * operations (which operation follows which in its sessions) and the client it calls from (its OAuth client and the
 * digest of its user agent; the user agent itself is text the requester writes). Learned from the agent's own allowed
 * requests before the current activity period, under the agent's learning key (A3-1); a person's request has none.
 *
 * @param observations          the agent's learned requests that state an operation or a client
 * @param usualTransitions      operation pairs ({@code READ>EXPORT}) and how often each was seen, most frequent first
 * @param usualClients          clients ({@code <client id or "no client"> #<user agent digest>}) and how often each was
 *                              seen, most frequent first
 * @param currentTransition     this request's pair, null when it is its session's first operation
 * @param currentTransitionSeen how often the learned requests show this request's pair
 * @param currentClient         this request's client in the same form
 * @param currentClientSeen     how often the learned requests show this request's client
 */
public record AgentBaselineView(int observations,
                                List<Count> usualTransitions,
                                List<Count> usualClients,
                                @Nullable String currentTransition,
                                int currentTransitionSeen,
                                @Nullable String currentClient,
                                int currentClientSeen) {

    /** The most transitions and clients a view lists. */
    public static final int LISTED_TRANSITIONS = 8;
    public static final int LISTED_CLIENTS = 5;

    /** The client value of a request that names no OAuth client (an agent signed in with its own account). */
    public static final String NO_CLIENT = "no-client";

    /** The separator of an operation pair. */
    public static final String THEN = ">";

    public AgentBaselineView {
        usualTransitions = usualTransitions == null ? List.of() : List.copyOf(usualTransitions);
        usualClients = usualClients == null ? List.of() : List.copyOf(usualClients);
    }

    /** One value and how often the learned requests show it. */
    public record Count(String value, int count) {
    }

    /**
     * What one learned (or the current) request of an agent states.
     *
     * @param clientId              its OAuth client, null without one
     * @param userAgentDigest       the digest of its user agent ({@link #digest}), null without a user agent
     * @param previousActionFamily  the operation before it in its session, null for the session's first
     * @param actionFamily          its operation
     */
    public record Facts(@Nullable String clientId, @Nullable String userAgentDigest,
                        @Nullable String previousActionFamily, @Nullable String actionFamily) {

        /** The operation pair, null when either side is unknown. */
        @Nullable
        public String transition() {
            return StringUtils.hasText(previousActionFamily) && StringUtils.hasText(actionFamily)
                    ? previousActionFamily + THEN + actionFamily : null;
        }

        /** The client in the form a view lists, null when neither a client nor a user agent is known. */
        @Nullable
        public String client() {
            if (!StringUtils.hasText(clientId) && !StringUtils.hasText(userAgentDigest)) {
                return null;
            }
            return (StringUtils.hasText(clientId) ? clientId : NO_CLIENT)
                    + (StringUtils.hasText(userAgentDigest) ? " #" + userAgentDigest : "");
        }

        public boolean empty() {
            return transition() == null && client() == null;
        }
    }

    public boolean observed() {
        return observations > 0;
    }

    /** The view of the learned requests' facts, with the current request's facts counted against it, not into it. */
    public static AgentBaselineView calculate(List<Facts> learned, @Nullable Facts current) {
        Map<String, Integer> transitions = new LinkedHashMap<>();
        Map<String, Integer> clients = new LinkedHashMap<>();
        int observations = 0;
        for (Facts facts : learned != null ? learned : List.<Facts>of()) {
            if (facts == null || facts.empty()) {
                continue;
            }
            observations++;
            if (facts.transition() != null) {
                transitions.merge(facts.transition(), 1, Integer::sum);
            }
            if (facts.client() != null) {
                clients.merge(facts.client(), 1, Integer::sum);
            }
        }
        String currentTransition = current != null ? current.transition() : null;
        String currentClient = current != null ? current.client() : null;
        return new AgentBaselineView(observations,
                ranked(transitions, LISTED_TRANSITIONS),
                ranked(clients, LISTED_CLIENTS),
                currentTransition,
                currentTransition != null ? transitions.getOrDefault(currentTransition, 0) : 0,
                currentClient,
                currentClient != null ? clients.getOrDefault(currentClient, 0) : 0);
    }

    /**
     * The digest of a user agent: the first 8 bytes of its SHA-256 in hex. The user agent is text the requester
     * writes, so the baseline keeps and shows only its digest; its text stays in the prompt's untrusted text.
     */
    @Nullable
    public static String digest(@Nullable String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return null;
        }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(userAgent.trim().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static List<Count> ranked(Map<String, Integer> counts, int limit) {
        List<Count> ranked = new ArrayList<>();
        counts.forEach((value, count) -> ranked.add(new Count(value, count)));
        // The most frequent first; equal counts keep the order first seen.
        ranked.sort(Comparator.comparingInt(Count::count).reversed());
        return ranked.size() > limit ? List.copyOf(ranked.subList(0, limit)) : ranked;
    }
}
