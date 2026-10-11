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
package io.contexa.contexacore.autonomous.context.collector;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Records what the context collectors observed about a request once its final decision is known (W2-7). While the
 * context of a request is resolved the collectors only read; they stage here the snapshot they gave and the
 * observations they would record. The place that knows the final decision commits them, once per request: resolving
 * the same request again returns the staged snapshot without reading or writing anything, and a second commit of the
 * same request does nothing. What is committed depends on the outcome: the session's narrative and the decision of
 * the request are always recorded, while the observations the usual behaviour is learned from are recorded only for
 * an allowed request whose decision is enforced.
 */
@Slf4j
public class ContextObservationRecorder {

    public static final String SESSION_NARRATIVE = "sessionNarrative";
    public static final String WORK_PROFILE = "workProfile";
    public static final String ROLE_SCOPE = "roleScope";

    private static final String ALLOW = "ALLOW";
    private static final int MAX_REQUESTS = 10_000;
    private static final long REQUEST_TTL_MINUTES = 30;

    /**
     * The outcome a commit records the staged observations under.
     *
     * @param dataStore the store the observations are recorded in
     * @param outcome   the final Zero Trust action ({@code ALLOW}, {@code CHALLENGE}, ...), {@link
     *                  SessionDecisionRecord#AUTHORIZATION_DENIED} for a refused authorization, or null when no decision
     *                  was reached
     * @param enforced  whether the decision is enforced (not a shadow decision)
     */
    public record Commit(SecurityContextDataStore dataStore, String outcome, boolean enforced) {

        /** Whether the request may become part of the usual behaviour: allowed by an enforced decision. */
        public boolean learnable() {
            return enforced && ALLOW.equalsIgnoreCase(String.valueOf(outcome));
        }

        public boolean authorizationDenied() {
            return SessionDecisionRecord.AUTHORIZATION_DENIED.equals(outcome);
        }
    }

    private record Staged(Object snapshot, Consumer<Commit> observations) {
    }

    private static final class Request {
        private final Map<String, Staged> staged = new LinkedHashMap<>();
        private boolean committed;
    }

    private final SecurityContextDataStore dataStore;
    private final Cache<String, Request> requests;

    public ContextObservationRecorder(SecurityContextDataStore dataStore) {
        this.dataStore = dataStore;
        this.requests = Caffeine.newBuilder()
                .maximumSize(MAX_REQUESTS)
                .expireAfterWrite(REQUEST_TTL_MINUTES, TimeUnit.MINUTES)
                .build();
    }

    /**
     * The request a collector observes: its request ID, else its correlation ID, else the event ID, with the protected
     * method it calls. One HTTP request can call several protected methods, each with its own decision and its own
     * observations; the same method again within the request is not analysed (rapid re-entry guard), so the method
     * tells the calls apart (P2 correction 4).
     */
    public static String requestKey(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        String request = null;
        if (metadata != null) {
            for (String key : new String[]{"requestId", "correlationId"}) {
                Object value = metadata.get(key);
                if (value != null && StringUtils.hasText(value.toString())) {
                    request = value.toString();
                    break;
                }
            }
        }
        if (request == null) {
            request = StringUtils.hasText(event.getEventId()) ? event.getEventId() : null;
        }
        if (request == null || metadata == null) {
            return request;
        }
        for (String key : new String[]{"protectableResourceId", "resourceId"}) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return request + "|" + value;
            }
        }
        return request;
    }

    /** The snapshot a collector already gave for the same request, if it did. */
    public <T> Optional<T> resolved(SecurityEvent event, String collector, Class<T> type) {
        String key = requestKey(event);
        if (key == null) {
            return Optional.empty();
        }
        Request request = requests.getIfPresent(key);
        if (request == null) {
            return Optional.empty();
        }
        synchronized (request) {
            Staged staged = request.staged.get(collector);
            return staged != null && type.isInstance(staged.snapshot()) ? Optional.of(type.cast(staged.snapshot()))
                    : Optional.empty();
        }
    }

    /**
     * Stages a collector's snapshot of the request and the observations to record when the decision is known. A
     * request without a key cannot be committed later, so its observations are recorded as a request that reached no
     * decision would be.
     */
    public void stage(SecurityEvent event, String collector, Object snapshot, Consumer<Commit> observations) {
        String key = requestKey(event);
        if (key == null) {
            record(observations, new Commit(dataStore, null, false));
            return;
        }
        Request request = requests.get(key, ignored -> new Request());
        synchronized (request) {
            if (request.committed) {
                return;
            }
            request.staged.put(collector, new Staged(snapshot, observations));
        }
    }

    /**
     * Records the request's staged observations under its final outcome, and the request in the session's decision
     * history when it reached a decision. A request already committed is not recorded again.
     */
    public void commit(SecurityEvent event, String outcome, boolean enforced) {
        String key = requestKey(event);
        if (key == null) {
            return;
        }
        Request request = requests.get(key, ignored -> new Request());
        Commit commit = new Commit(dataStore, outcome, enforced);
        synchronized (request) {
            if (request.committed) {
                return;
            }
            request.committed = true;
            for (Staged staged : request.staged.values()) {
                record(staged.observations(), commit);
            }
        }
        if (outcome != null && event.getSessionId() != null && !event.getSessionId().isBlank() && dataStore != null) {
            try {
                dataStore.addSessionDecision(event.getSessionId().trim(), SessionDecisionRecord.of(event, outcome).encode());
            } catch (RuntimeException e) {
                log.error("Failed to record the session decision of a request", e);
            }
        }
    }

    /** Whether the request's observations were already committed. */
    public boolean committed(SecurityEvent event) {
        String key = requestKey(event);
        Request request = key != null ? requests.getIfPresent(key) : null;
        if (request == null) {
            return false;
        }
        synchronized (request) {
            return request.committed;
        }
    }

    private static void record(Consumer<Commit> observations, Commit commit) {
        if (observations == null || commit.dataStore() == null) {
            return;
        }
        try {
            observations.accept(commit);
        } catch (RuntimeException e) {
            log.error("Failed to record the context observations of a request", e);
        }
    }
}
