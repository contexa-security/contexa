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

import java.util.Objects;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.SessionStart;
import io.contexa.contexacore.autonomous.context.support.MetadataValueResolver;
import io.contexa.contexacore.autonomous.context.support.NetworkZone;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;

import io.contexa.contexacore.autonomous.context.policy.PromptRelevantRequestPathPolicy;

public class DefaultSessionNarrativeCollector implements SessionNarrativeCollector {

    private static final int MAX_SEQUENCE_SIZE = 10;
    private static final int BURST_PROTECTABLE_THRESHOLD = 3;
    private static final int MAX_SESSION_DECISIONS = 100;
    /** The span the user's request rate is counted over (W5-10 D5). */
    private static final long HOUR_MS = 60L * 60L * 1_000L;
    private static final long BURST_INTERVAL_THRESHOLD_MS = 2_000L;

    private final SecurityContextDataStore dataStore;
    private final ContextObservationRecorder recorder;

    /** A collector that records through a recorder of its own, committed by whoever holds it. */
    public DefaultSessionNarrativeCollector(SecurityContextDataStore dataStore) {
        this(dataStore, new ContextObservationRecorder(dataStore));
    }

    public DefaultSessionNarrativeCollector(SecurityContextDataStore dataStore, ContextObservationRecorder recorder) {
        this.dataStore = dataStore;
        this.recorder = recorder;
    }

    public ContextObservationRecorder recorder() {
        return recorder;
    }

    /**
     * The session's narrative up to this request. The collector only reads the store and adds this request to what it
     * read; the request's own facts are recorded once its decision is known (W2-7), so resolving the same request
     * again neither reads a second time nor records the request twice.
     */
    @Override
    public Optional<SessionNarrativeSnapshot> collect(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getSessionId())) {
            return Optional.empty();
        }
        Optional<SessionNarrativeSnapshot> resolved = recorder.resolved(event,
                ContextObservationRecorder.SESSION_NARRATIVE, SessionNarrativeSnapshot.class);
        if (resolved.isPresent()) {
            return resolved;
        }

        String sessionId = event.getSessionId().trim();
        long currentTimestamp = resolveTimestamp(event);
        Long storedStart = dataStore.getSessionStartedAt(sessionId);
        long sessionStartedAt = storedStart != null ? storedStart : currentTimestamp;

        Long previousRequestTimestamp = dataStore.getSessionLastRequestTime(sessionId);
        String previousPath = resolveExplicitPreviousPath(event);
        if (!StringUtils.hasText(previousPath)) {
            previousPath = dataStore.getSessionPreviousPath(sessionId);
        }
        String currentPath = resolveRequestPath(event);
        if (!PromptRelevantRequestPathPolicy.isPromptRelevantPath(currentPath)) {
            // A request outside the narrative still opens the session.
            recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, null,
                    commit -> startSession(commit.dataStore(), sessionId, currentTimestamp));
            return Optional.empty();
        }
        String currentActionFamily = resolveActionFamily(event);
        boolean protectableRequest = isProtectableRequest(event);
        String protectablePath = protectableRequest && StringUtils.hasText(currentPath) ? currentPath : null;

        Long lastRequestIntervalMs = null;
        if (previousRequestTimestamp != null && currentTimestamp >= previousRequestTimestamp) {
            lastRequestIntervalMs = currentTimestamp - previousRequestTimestamp;
        }

        // Families stored before the one vocabulary (CREATE, UPDATE) read as the family they name today.
        List<String> actionSequence = appended(dataStore.getRecentSessionNarrativeActionFamilies(sessionId,
                        MAX_SEQUENCE_SIZE).stream()
                .map(ActionFamily::nameOrRaw)
                .filter(Objects::nonNull)
                .toList(), StringUtils.hasText(currentActionFamily) ? currentActionFamily : null, MAX_SEQUENCE_SIZE);
        List<String> protectableSequence = appended(
                dataStore.getRecentSessionProtectableAccesses(sessionId, MAX_SEQUENCE_SIZE), protectablePath,
                MAX_SEQUENCE_SIZE);
        List<Long> recentIntervals = appended(
                dataStore.getRecentSessionRequestIntervals(sessionId, BURST_PROTECTABLE_THRESHOLD), lastRequestIntervalMs,
                BURST_PROTECTABLE_THRESHOLD);
        boolean burstPattern = detectBurst(protectableSequence, recentIntervals);
        // The session counts from its sign-in (or its creation) when that is known, else from its first analysed
        // request; the basis goes with the age.
        SessionStart start = SessionStart.of(event);
        long sessionStartMs = start != null ? start.at().toEpochMilli() : sessionStartedAt;
        String sessionAgeBasis = start != null ? start.basis() : SessionStart.FIRST_ANALYSED_REQUEST;
        int sessionAgeMinutes = Math.max(0, (int) ((currentTimestamp - sessionStartMs) / 60_000L));
        String previousActionFamily = actionSequence.size() >= 2 ? actionSequence.get(actionSequence.size() - 2) : null;
        // The session's earlier decisions (this request has none yet): their counts and the most recent of them.
        List<SessionDecisionRecord> decisions = sessionDecisions(sessionId);
        // The client the session first came from beside this request's (W2-14): a change of device or of network within
        // one session is a fact of its own. The first client is recorded once a decision on the request is known.
        SessionClient currentClient = SessionClient.of(event);
        SessionClient firstClient = SessionClient.decode(dataStore.getSessionFirstClient(sessionId));

        SessionNarrativeSnapshot snapshot = SessionNarrativeSnapshot.builder()
                .sessionId(sessionId)
                .sessionAgeMinutes(sessionAgeMinutes)
                .sessionAgeBasis(sessionAgeBasis)
                .newSession(previousRequestTimestamp == null)
                .previousPath(previousPath)
                .previousActionFamily(previousActionFamily)
                .lastRequestIntervalMs(lastRequestIntervalMs)
                .sessionActionSequence(actionSequence)
                .sessionProtectableSequence(protectableSequence)
                .burstPattern(burstPattern)
                .recentChallengeCount(countOutcome(decisions, "CHALLENGE"))
                .recentBlockCount(countOutcome(decisions, "BLOCK"))
                .recentEscalationCount(countOutcome(decisions, "ESCALATE"))
                .sessionDecisionHistory(decisions == null ? List.of() : decisions.stream()
                        .skip(Math.max(0, decisions.size() - MAX_SEQUENCE_SIZE))
                        .map(SessionDecisionRecord::describe)
                        .toList())
                // Every stored decision, so that what the session already did under an approval is counted whole.
                .sessionDecisions(decisions == null ? List.of() : decisions)
                .userRequestsLastHour(userRequestsLastHour(event, sessionId, decisions, currentTimestamp))
                .sessionDeviceChange(SessionClient.deviceChange(firstClient, currentClient))
                .sessionNetworkChange(SessionClient.networkChange(firstClient, currentClient))
                .summary(buildSummary(sessionAgeMinutes, previousPath, previousActionFamily, lastRequestIntervalMs, actionSequence, burstPattern))
                .build();

        Long interval = lastRequestIntervalMs;
        recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, snapshot, commit -> {
            SecurityContextDataStore store = commit.dataStore();
            startSession(store, sessionId, currentTimestamp);
            // A request is recorded once its decision is known, which can be after a later request of the session
            // is recorded; the store keeps the request's time so that the session reads in the order made (G4-2).
            if (StringUtils.hasText(currentActionFamily)) {
                store.addSessionNarrativeActionFamily(sessionId, currentActionFamily, currentTimestamp);
            }
            if (protectablePath != null) {
                store.addSessionProtectableAccess(sessionId, protectablePath, currentTimestamp);
            }
            if (interval != null) {
                store.addSessionRequestInterval(sessionId, interval, currentTimestamp);
            }
            store.recordSessionLastRequest(sessionId, currentTimestamp,
                    StringUtils.hasText(currentPath) ? currentPath : null);
            if (currentClient != null) {
                store.setSessionFirstClientIfAbsent(sessionId, currentClient.encode());
            }
        });
        return Optional.of(snapshot);
    }

    /**
     * The user's decisions in the last 60 minutes of the event clock across the sessions the user holds, this request
     * included (W5-10 D5); null when the store keeps no session list. A refused or held request counts as much as an
     * allowed one: a burst is a burst whatever was decided.
     */
    private Integer userRequestsLastHour(SecurityEvent event, String sessionId, List<SessionDecisionRecord> decisions,
                                         long now) {
        Set<String> tracked = StringUtils.hasText(event.getUserId())
                ? dataStore.getUserSessions(event.getUserId().trim()) : null;
        if (tracked == null) {
            return null;
        }
        Set<String> sessions = new LinkedHashSet<>(tracked);
        sessions.add(sessionId);
        int count = 1;
        for (String session : sessions) {
            List<SessionDecisionRecord> records = session.equals(sessionId) ? decisions : sessionDecisions(session);
            if (records == null) {
                continue;
            }
            for (SessionDecisionRecord record : records) {
                if (record != null && record.at() != null && record.at().toEpochMilli() <= now
                        && now - record.at().toEpochMilli() < HOUR_MS) {
                    count++;
                }
            }
        }
        return count;
    }

    private static void startSession(SecurityContextDataStore store, String sessionId, long timestamp) {
        if (store.getSessionStartedAt(sessionId) == null) {
            store.setSessionStartedAt(sessionId, timestamp);
        }
    }

    /** What the store read with this request's value after it, the most recent {@code limit} kept. */
    private static <T> List<T> appended(List<T> stored, T current, int limit) {
        List<T> values = new ArrayList<>(stored == null ? List.of() : stored);
        if (current != null) {
            values.add(current);
        }
        return Collections.unmodifiableList(values.size() > limit
                ? new ArrayList<>(values.subList(values.size() - limit, values.size())) : values);
    }

    /**
     * The session's recorded decisions in the order their requests were made; null when the store keeps no decision
     * history. A decision is recorded once known, which can be out of the order the requests were made (G4-2); a
     * decision without its time keeps its place after the one before it.
     */
    private List<SessionDecisionRecord> sessionDecisions(String sessionId) {
        List<String> stored = dataStore.getRecentSessionDecisions(sessionId, MAX_SESSION_DECISIONS);
        if (stored == null) {
            return null;
        }
        List<SessionDecisionRecord> decisions = new ArrayList<>();
        List<Instant> times = new ArrayList<>();
        Instant at = Instant.MIN;
        for (String line : stored) {
            SessionDecisionRecord decision = SessionDecisionRecord.decode(line);
            if (decision == null) {
                continue;
            }
            at = decision.at() != null ? decision.at() : at;
            decisions.add(decision);
            times.add(at);
        }
        List<Integer> order = new ArrayList<>();
        for (int index = 0; index < decisions.size(); index++) {
            order.add(index);
        }
        order.sort(Comparator.comparing(times::get));
        return order.stream().map(decisions::get).toList();
    }

    private static Integer countOutcome(List<SessionDecisionRecord> decisions, String outcome) {
        if (decisions == null) {
            return null;
        }
        return (int) decisions.stream().filter(decision -> outcome.equalsIgnoreCase(String.valueOf(decision.outcome()))).count();
    }

    private boolean detectBurst(List<String> protectableSequence, List<Long> recentIntervals) {
        if (protectableSequence == null || protectableSequence.size() < BURST_PROTECTABLE_THRESHOLD) {
            return false;
        }
        if (recentIntervals == null || recentIntervals.size() < BURST_PROTECTABLE_THRESHOLD - 1) {
            return false;
        }
        return recentIntervals.stream()
                .skip(Math.max(0, recentIntervals.size() - (BURST_PROTECTABLE_THRESHOLD - 1)))
                .allMatch(interval -> interval != null && interval <= BURST_INTERVAL_THRESHOLD_MS);
    }

    private String buildSummary(int sessionAgeMinutes,
                                String previousPath,
                                String previousActionFamily,
                                Long lastRequestIntervalMs,
                                List<String> actionSequence,
                                boolean burstPattern) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("Session age " + sessionAgeMinutes + "m");
        if (StringUtils.hasText(previousPath)) {
            joiner.add("Previous path " + previousPath);
        }
        if (StringUtils.hasText(previousActionFamily)) {
            joiner.add("Previous action " + previousActionFamily);
        }
        if (lastRequestIntervalMs != null) {
            joiner.add("Inter-request gap " + lastRequestIntervalMs + "ms");
        }
        if (actionSequence != null && !actionSequence.isEmpty()) {
            joiner.add("Recent actions " + String.join(" -> ", actionSequence));
        }
        if (burstPattern) {
            joiner.add("Burst pacing detected");
        }
        return joiner.toString();
    }

    private long resolveTimestamp(SecurityEvent event) {
        if (event.getTimestamp() != null) {
            return event.getTimestamp().toEpochMilli();
        }
        return System.currentTimeMillis();
    }

    private String resolveExplicitPreviousPath(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        Object previousPath = metadata.get("previousPath");
        if (previousPath == null) {
            previousPath = metadata.get("previous_path");
        }
        if (previousPath == null) {
            return null;
        }
        String normalized = previousPath.toString().trim();
        return StringUtils.hasText(normalized) ? normalized : null;
    }
    private String resolveRequestPath(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        Object requestPath = metadata.get("requestPath");
        if (requestPath == null) {
            requestPath = metadata.get("targetResource");
        }
        if (requestPath == null) {
            requestPath = metadata.get("protectableResource");
        }
        if (requestPath == null) {
            return null;
        }
        String normalized = requestPath.toString().trim();
        return StringUtils.hasText(normalized) ? normalized : null;
    }

    /** The request's action family, the same one the context gives it; an event description is not an action. */
    private String resolveActionFamily(SecurityEvent event) {
        return ActionFamilyResolver.resolve(event.getMetadata()).family().name();
    }

    private boolean isProtectableRequest(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return false;
        }

        Boolean explicitFlag = resolveBoolean(
                metadata.get("isProtectable"),
                metadata.get("protectable"),
                metadata.get("protectableRequest"));
        if (explicitFlag != null) {
            return explicitFlag;
        }

        if (metadata.get("protectableResource") != null) {
            return true;
        }

        if (metadata.containsKey("granted")
                && (metadata.containsKey("className") || metadata.containsKey("methodName"))) {
            return true;
        }

        return Boolean.TRUE.equals(resolveBoolean(
                metadata.get("isSensitiveResource"),
                metadata.get("privileged"),
                metadata.get("protectablePrivileged"),
                metadata.get("exportSensitive")));
    }

    private Boolean resolveBoolean(Object... candidates) {
        return MetadataValueResolver.resolveBoolean(candidates);
    }

    /**
     * A request's client as the session narrative compares it (W2-14): whether the request gave a User-Agent, the
     * operating system and browser it names, and the network of the request address with the zone the host declares.
     * The store keeps it as one line.
     */
    record SessionClient(boolean userAgentGiven, String operatingSystem, String browser, String network, String zone) {

        private static final String SEPARATOR = "|";
        private static final String USER_AGENT_GIVEN = "UA";
        private static final int PARTS = 5;

        /** The request's client; null when the request gives neither a User-Agent nor an address. */
        static SessionClient of(SecurityEvent event) {
            String userAgent = event.getUserAgent();
            boolean userAgentGiven = StringUtils.hasText(userAgent);
            String network = SecuritySemanticNormalizer.normalizeNetwork(event.getSourceIp(), null);
            if (!userAgentGiven && network == null) {
                return null;
            }
            Map<String, Object> metadata = event.getMetadata();
            return new SessionClient(userAgentGiven,
                    userAgentGiven ? SecurityEventEnricher.extractOSFromUserAgent(userAgent) : null,
                    userAgentGiven ? SecurityEventEnricher.extractBrowserSignature(userAgent) : null,
                    network,
                    metadata != null ? NetworkZone.nameOf(metadata.get("networkZone")) : null);
        }

        String encode() {
            return String.join(SEPARATOR, userAgentGiven ? USER_AGENT_GIVEN : "", part(operatingSystem), part(browser),
                    part(network), part(zone));
        }

        /** The client a stored line names; null for no line or for a line in a form this version does not read. */
        static SessionClient decode(String line) {
            if (!StringUtils.hasText(line)) {
                return null;
            }
            String[] parts = line.split("\\|", -1);
            if (parts.length != PARTS) {
                return null;
            }
            return new SessionClient(USER_AGENT_GIVEN.equals(parts[0]), blankToNull(parts[1]), blankToNull(parts[2]),
                    blankToNull(parts[3]), blankToNull(parts[4]));
        }

        /**
         * "first -> current" when both requests gave a User-Agent and their operating system or browser differs; a
         * browser's version is set aside, since a browser updates within a session. Null otherwise.
         */
        static String deviceChange(SessionClient first, SessionClient current) {
            if (first == null || current == null || !first.userAgentGiven() || !current.userAgentGiven()) {
                return null;
            }
            boolean sameSystem = Objects.equals(first.operatingSystem(), current.operatingSystem());
            boolean sameBrowser = Objects.equals(browserName(first.browser()), browserName(current.browser()));
            return sameSystem && sameBrowser ? null : first.device() + " -> " + current.device();
        }

        /** "first -> current" when both requests came from a known network and the two differ; null otherwise. */
        static String networkChange(SessionClient first, SessionClient current) {
            if (first == null || current == null || first.network() == null || current.network() == null
                    || SecuritySemanticNormalizer.sameNetwork(first.network(), current.network())) {
                return null;
            }
            return first.networkLabel() + " -> " + current.networkLabel();
        }

        private String device() {
            String device = SecuritySemanticNormalizer.device(browser, operatingSystem);
            if (device != null) {
                return device;
            }
            return operatingSystem != null ? operatingSystem : "a client that names no browser or operating system";
        }

        private String networkLabel() {
            return zone != null ? network + " (" + zone + ")" : network;
        }

        private static String browserName(String browser) {
            if (browser == null) {
                return null;
            }
            int slash = browser.indexOf('/');
            return (slash >= 0 ? browser.substring(0, slash) : browser).toLowerCase(Locale.ROOT);
        }

        private static String part(String value) {
            return value == null ? "" : value;
        }

        private static String blankToNull(String value) {
            return StringUtils.hasText(value) ? value : null;
        }
    }
}

