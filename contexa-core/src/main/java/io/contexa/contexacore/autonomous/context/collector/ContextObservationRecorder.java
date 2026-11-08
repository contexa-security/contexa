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
import com.github.benmanes.caffeine.cache.RemovalCause;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.bridge.AgentSessionKey;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Records what the context collectors observed about a request once its final decision is known (W2-7). While the
 * context of a request is resolved the collectors only read; they stage here the snapshot they gave and the
 * observations they would record. The place that knows the final decision commits them, once per request: resolving
 * the same request again returns the staged snapshot without reading or writing anything, and a second commit of the
 * same request does nothing. What is committed depends on the outcome: the session's narrative and the decision of
 * the request are always recorded, while the observations the usual behaviour is learned from are recorded only for
 * an allowed request whose decision is enforced.
 * <p>
 * PR-91: what the requests hold has a size limit of its own, a share of the heap, beside their number: a snapshot of a
 * session holds up to a hundred decoded decisions, so ten thousand of them filled a customer's heap. Past the limit the
 * committed requests give up their snapshots first, the longest committed first: a later resolution of such a request
 * reads the session again and records nothing, and its committed mark stays. Only when those are gone do the requests
 * still waiting for their commit go, the oldest first: a commit that does come then records the decision of the
 * request and not the observations it no longer holds. With URLs of a usual length that takes more analyses at once
 * than the analysis executor runs. What a new request reads does not depend on the limit while that does not happen.
 */
@Slf4j
public class ContextObservationRecorder {

    public static final String SESSION_NARRATIVE = "sessionNarrative";
    public static final String WORK_PROFILE = "workProfile";
    public static final String ROLE_SCOPE = "roleScope";

    private static final String ALLOW = "ALLOW";
    private static final int MAX_REQUESTS = 10_000;
    private static final long REQUEST_TTL_MINUTES = 30;
    /** PR-91: what the requests hold may take a twentieth of the maximum heap, within these bounds. */
    private static final int HELD_HEAP_SHARE_DIVISOR = 20;
    private static final long MIN_HELD_BYTES = 16L * 1024 * 1024;
    private static final long MAX_HELD_BYTES = 256L * 1024 * 1024;
    /** What a staged entry takes around its snapshot: the map entry, the staged record, the snapshot object. */
    private static final long STAGED_ENTRY_BYTES = 256;
    /** What observations waiting for the commit hold: the three or four of a request share an event of tens of KB. */
    private static final long WAITING_OBSERVATIONS_BYTES = 16L * 1024;
    /** How many waiting requests are given up between two warnings. */
    private static final int WAITING_RELEASES_PER_WARNING = 1_000;

    /**
     * The outcome a commit records the staged observations under.
     *
     * @param dataStore the store the observations are recorded in
     * @param outcome   the final Zero Trust action ({@code ALLOW}, {@code CHALLENGE}, ...), {@link
     *                  SessionDecisionRecord#AUTHORIZATION_DENIED} for a refused authorization, or null when no decision
     *                  was reached
     * @param enforced  whether the decision counts: the one in force, or in SHADOW the one that stands in the memory of
     *                  SHADOW. SHADOW decides as ENFORCE does, so what it learns is what ENFORCE learns. A decision that
     *                  only stands aside (a stricter one is in force, or the memory failed) does not count.
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

    /** A snapshot and the observations waiting for the commit, with the bytes they are counted at. */
    private record Staged(Object snapshot, Consumer<Commit> observations, long bytes) {

        private static Staged of(Object snapshot, Consumer<Commit> observations) {
            return new Staged(snapshot, observations, STAGED_ENTRY_BYTES + snapshotBytes(snapshot)
                    + (observations != null ? WAITING_OBSERVATIONS_BYTES : 0));
        }

        /** The same snapshot once the observations ran: what they held is no longer counted. */
        private Staged withoutObservations() {
            return observations == null ? this : new Staged(snapshot, null, bytes - WAITING_OBSERVATIONS_BYTES);
        }

        /** Its text at two bytes a character: about what its strings and records take, whatever fields it has. */
        private static long snapshotBytes(Object snapshot) {
            return snapshot != null ? 2L * snapshot.toString().length() : 0;
        }
    }

    private static final class Request {
        private final Map<String, Staged> staged = new LinkedHashMap<>();
        private boolean committed;
        /** What {@link #staged} is counted at, and whether the request left the cache; guarded by the held lock. */
        private long heldBytes;
        private boolean removed;
    }

    private final SecurityContextDataStore dataStore;
    private final Cache<String, Request> requests;
    private final long heldBudgetBytes;
    /**
     * Guards the two orders below and the count. It is taken last and nothing is called under it: the cache takes it
     * while it removes a request, so it must never wait for the lock of a request.
     */
    private final Object heldLock = new Object();
    /** The committed requests that hold a snapshot, in the order they were committed. */
    private final Set<Request> committedHolding = new LinkedHashSet<>();
    /** The requests waiting for a commit that hold something, in the order they first staged it. */
    private final Set<Request> waitingHolding = new LinkedHashSet<>();
    private long heldBytes;
    private final AtomicLong waitingReleases = new AtomicLong();

    public ContextObservationRecorder(SecurityContextDataStore dataStore) {
        this(dataStore, defaultHeldBudgetBytes(Runtime.getRuntime().maxMemory()));
    }

    ContextObservationRecorder(SecurityContextDataStore dataStore, long heldBudgetBytes) {
        this.dataStore = dataStore;
        this.heldBudgetBytes = heldBudgetBytes;
        this.requests = Caffeine.newBuilder()
                .maximumSize(MAX_REQUESTS)
                .expireAfterWrite(REQUEST_TTL_MINUTES, TimeUnit.MINUTES)
                .evictionListener((String key, Request request, RemovalCause cause) -> removed(request))
                .build();
    }

    /**
     * PR-91: the default limit of what the requests hold for a maximum heap of {@code maxHeapBytes}: a twentieth of it,
     * between 16 MiB and 256 MiB. A 384 MiB heap gives 19.2 MiB, 512 MiB 25.6 MiB, 2 GiB 102.4 MiB, 5 GiB or more and a
     * JVM without a heap limit 256 MiB.
     */
    static long defaultHeldBudgetBytes(long maxHeapBytes) {
        return Math.max(MIN_HELD_BYTES, Math.min(MAX_HELD_BYTES, maxHeapBytes / HELD_HEAP_SHARE_DIVISOR));
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
        Staged staged = Staged.of(snapshot, observations);
        Request request = requests.get(key, ignored -> new Request());
        synchronized (request) {
            if (request.committed) {
                return;
            }
            request.staged.put(collector, staged);
            countHeld(request);
        }
        releaseOverBudget();
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
            // QF-42: the observations ran and are never run again; they hold the whole event, so only the mark and
            // the snapshots a later resolution of the request is answered with stay.
            request.staged.replaceAll((collector, staged) -> staged.withoutObservations());
            request.staged.values().removeIf(staged -> staged.snapshot() == null);
            countHeld(request);
        }
        releaseOverBudget();
        if (outcome != null && event.getSessionId() != null && !event.getSessionId().isBlank() && dataStore != null) {
            String sessionId = event.getSessionId().trim();
            try {
                dataStore.addSessionDecision(sessionId, SessionDecisionRecord.of(event, outcome).encode());
                trackUserSession(event, sessionId);
            } catch (RuntimeException e) {
                log.error("Failed to record the session decision of a request", e);
            }
        }
    }

    /**
     * Lists the session among the user's sessions, so the user's recent requests are counted across them (CF-07): a
     * token request's session is its login ({@code sid}), which the session store did not list. An agent acting for a
     * person has its own session, which is not counted as the person's (A1-11).
     */
    private void trackUserSession(SecurityEvent event, String sessionId) {
        String userId = event.getUserId() != null ? event.getUserId().trim() : "";
        if (userId.isEmpty() || sessionId.startsWith(AgentSessionKey.AGENT_PREFIX + ":")) {
            return;
        }
        dataStore.trackUserSession(userId, sessionId);
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

    /** Whether something is staged for the request: an analysis of it is running, or it kept its snapshots. */
    public boolean staged(SecurityEvent event) {
        String key = requestKey(event);
        Request request = key != null ? requests.getIfPresent(key) : null;
        if (request == null) {
            return false;
        }
        synchronized (request) {
            return !request.staged.isEmpty();
        }
    }

    /**
     * Gives up what a committed request holds, its mark staying: for a request nothing resolves again. A later
     * resolution reads the session again and records nothing.
     */
    public void release(SecurityEvent event) {
        String key = requestKey(event);
        Request request = key != null ? requests.getIfPresent(key) : null;
        if (request != null) {
            release(request);
        }
    }

    /** How many observations of the request are staged and not yet released. */
    int stagedObservations(SecurityEvent event) {
        String key = requestKey(event);
        Request request = key != null ? requests.getIfPresent(key) : null;
        if (request == null) {
            return 0;
        }
        synchronized (request) {
            return (int) request.staged.values().stream().filter(staged -> staged.observations() != null).count();
        }
    }

    /** The bytes what the requests hold is counted at (PR-91). */
    long heldBytes() {
        requests.cleanUp();
        synchronized (heldLock) {
            return heldBytes;
        }
    }

    /** How many requests hold something (PR-91). */
    int heldRequests() {
        requests.cleanUp();
        synchronized (heldLock) {
            return committedHolding.size() + waitingHolding.size();
        }
    }

    /** Counts what the request holds now; the caller holds the request's lock. */
    private void countHeld(Request request) {
        long bytes = request.staged.values().stream().mapToLong(Staged::bytes).sum();
        synchronized (heldLock) {
            if (request.removed) {
                return;
            }
            heldBytes += bytes - request.heldBytes;
            request.heldBytes = bytes;
            if (bytes == 0) {
                waitingHolding.remove(request);
                committedHolding.remove(request);
            } else if (request.committed) {
                waitingHolding.remove(request);
                committedHolding.add(request);
            } else {
                // A request staging more keeps the place it has.
                waitingHolding.add(request);
            }
        }
    }

    /** The cache removed the request, and what it held with it. */
    private void removed(Request request) {
        synchronized (heldLock) {
            request.removed = true;
            heldBytes -= request.heldBytes;
            request.heldBytes = 0;
            committedHolding.remove(request);
            waitingHolding.remove(request);
        }
    }

    /** Gives up what the requests hold past the limit, in the order the class comment gives. */
    private void releaseOverBudget() {
        Request oldest;
        while ((oldest = nextOverBudget()) != null) {
            if (release(oldest)) {
                long released = waitingReleases.getAndIncrement();
                if (released % WAITING_RELEASES_PER_WARNING == 0) {
                    log.warn("The requests waiting for their decision hold more than {} bytes: the oldest gave up its "
                            + "observations, {} requests so far", heldBudgetBytes, released + 1);
                }
            }
        }
    }

    private Request nextOverBudget() {
        synchronized (heldLock) {
            if (heldBytes <= heldBudgetBytes) {
                return null;
            }
            Iterator<Request> oldest = (committedHolding.isEmpty() ? waitingHolding : committedHolding).iterator();
            return oldest.hasNext() ? oldest.next() : null;
        }
    }

    /** Whether the request gave up something that was waiting for its commit. */
    private boolean release(Request request) {
        synchronized (request) {
            boolean waiting = !request.committed && !request.staged.isEmpty();
            request.staged.clear();
            countHeld(request);
            return waiting;
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
