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
package io.contexa.contexacore.autonomous.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Learns, once the user is verified, the request a restriction stopped (W5-2). When the engine enforces CHALLENGE,
 * ESCALATE or BLOCK on an analysed request, the request's facts are kept. When the user then passes the step-up the
 * decision asked for, or an administrator releases the block with ALLOW, those facts are learned: the baseline and the
 * past records learn the request's own path, resource, action, size and time, and the work profile adds the request as
 * an observation at a reduced weight. A request without kept facts is not learned here.
 */
@Slf4j
public class VerificationLearningService {

    /** The canonical context the decision used, put on the event when the prompt is built. */
    private static final String DECIDED_CONTEXT = "sealedEvidence.canonicalContext";

    /** The metadata of a learned request that names how its user was verified. */
    public static final String VERIFIED_BY = "verifiedBy";
    /** The metadata of a learned request that gives the weight it is learned at. */
    public static final String VERIFICATION_WEIGHT = "verificationWeight";
    static final String STEP_UP_REASONING = "Allowed after the user passed the step-up verification the decision "
            + "asked for; the request is learned at a reduced weight";
    private static final double DEFAULT_WEIGHT = 0.5;
    private static final Set<ZeroTrustAction> HELD = EnumSet.of(
            ZeroTrustAction.CHALLENGE, ZeroTrustAction.ESCALATE, ZeroTrustAction.BLOCK);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> RECORD = new TypeReference<>() {
    };

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final ProtectableWorkProfileCollector workProfileCollector;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    public VerificationLearningService(SecurityContextDataStore dataStore,
                                       @Nullable SecurityLearningService securityLearningService,
                                       @Nullable ProtectableWorkProfileCollector workProfileCollector,
                                       @Nullable SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.dataStore = dataStore;
        this.securityLearningService = securityLearningService;
        this.workProfileCollector = workProfileCollector;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    /** Keeps the facts of an analysed request the enforced action stops; any other action keeps nothing. */
    public void hold(SecurityEvent event, ZeroTrustAction action) {
        if (event == null || action == null || !HELD.contains(action) || !StringUtils.hasText(event.getUserId())
                || dataStore == null) {
            return;
        }
        String requestId = requestIdOf(event);
        if (requestId == null) {
            return;
        }
        try {
            dataStore.holdVerificationLearning(event.getUserId().trim(), requestId, encode(event));
        } catch (Exception e) {
            log.error("Failed to hold a stopped request for learning after verification: userId={}",
                    event.getUserId(), e);
        }
    }

    /** How the user was verified before the request is learned. */
    public enum Verification {
        /** The user passed the step-up the decision asked for. */
        STEP_UP,
        /** An administrator released the block with ALLOW. */
        ADMIN_RELEASE
    }

    /**
     * Takes, once, the facts kept for the user's request: the request as it was made, under a new event id, naming how
     * its user was verified and the weight it is learned at.
     */
    public Optional<SecurityEvent> take(String userId, String requestId, Verification verification) {
        Optional<SecurityEvent> held = takeHeld(userId, requestId);
        held.ifPresent(event -> {
            event.addMetadata(VERIFIED_BY, verification != null ? verification.name() : null);
            event.addMetadata(VERIFICATION_WEIGHT, weight());
        });
        return held;
    }

    private Optional<SecurityEvent> takeHeld(String userId, String requestId) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(requestId) || dataStore == null) {
            return Optional.empty();
        }
        try {
            String record = dataStore.takeVerificationLearning(userId.trim(), requestId);
            return record == null ? Optional.empty() : Optional.of(decode(record));
        } catch (Exception e) {
            log.error("Failed to take a request held for learning after verification: userId={}", userId, e);
            return Optional.empty();
        }
    }

    /**
     * Learns the user's request the step-up answered, from its kept facts: the baseline and the past records, and the
     * work profile at the reduced weight. False when no facts are kept for it.
     */
    public boolean learnStepUp(String userId, String requestId) {
        Optional<SecurityEvent> held = take(userId, requestId, Verification.STEP_UP);
        if (held.isEmpty()) {
            return false;
        }
        SecurityEvent event = held.get();
        if (securityLearningService != null) {
            SecurityDecision decision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .confidence(0.95)
                    .riskScore(0.05)
                    .reasoning(STEP_UP_REASONING)
                    .analysisTime(System.currentTimeMillis())
                    .build();
            securityLearningService.learnAndStore(userId.trim(), decision, event);
        }
        learnWorkProfile(event);
        return true;
    }

    /** Adds the request to the user's work profile at the reduced weight. */
    public void learnWorkProfile(SecurityEvent event) {
        if (event == null || workProfileCollector == null) {
            return;
        }
        try {
            workProfileCollector.recordVerified(event, weight());
        } catch (Exception e) {
            log.error("Failed to learn a verified request in the work profile: userId={}", event.getUserId(), e);
        }
    }

    private double weight() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getBaseline() == null
                || securityZeroTrustProperties.getBaseline().getLearning() == null) {
            return DEFAULT_WEIGHT;
        }
        double weight = securityZeroTrustProperties.getBaseline().getLearning().getVerifiedWeight();
        return Double.isNaN(weight) ? DEFAULT_WEIGHT : Math.min(1.0, Math.max(0.0, weight));
    }

    private static String requestIdOf(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null) {
            return null;
        }
        for (String key : new String[]{"requestId", "correlationId"}) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString();
            }
        }
        return null;
    }

    private static String encode(SecurityEvent event) throws Exception {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("timestamp", event.getTimestamp() != null ? event.getTimestamp().toEpochMilli() : null);
        record.put("userId", event.getUserId());
        record.put("userName", event.getUserName());
        record.put("sessionId", event.getSessionId());
        record.put("sourceIp", event.getSourceIp());
        record.put("userAgent", event.getUserAgent());
        record.put("description", event.getDescription());
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (event.getMetadata() != null) {
            event.getMetadata().forEach((key, value) -> {
                if (plain(value)) {
                    metadata.put(key, value);
                }
            });
        }
        // The canonical context is not kept, so the item count and network zone the decision used (W3-3) are kept as
        // the plain values the learning after the check reads in its place.
        if (event.getMetadata() != null
                && event.getMetadata().get(DECIDED_CONTEXT) instanceof CanonicalSecurityContext decided) {
            if (decided.getResource() != null && decided.getResource().getRequestedItems() != null) {
                metadata.put("requestItems", decided.getResource().getRequestedItems());
            }
            if (decided.getLocation() != null && StringUtils.hasText(decided.getLocation().getNetworkZone())) {
                metadata.put("networkZone", decided.getLocation().getNetworkZone());
            }
        }
        record.put("metadata", metadata);
        return JSON.writeValueAsString(record);
    }

    @SuppressWarnings("unchecked")
    private static SecurityEvent decode(String text) throws Exception {
        Map<String, Object> record = JSON.readValue(text, RECORD);
        Object timestamp = record.get("timestamp");
        SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.IAM)
                .timestamp(timestamp instanceof Number at ? Instant.ofEpochMilli(at.longValue()) : null)
                .userId(text(record.get("userId")))
                .userName(text(record.get("userName")))
                .sessionId(text(record.get("sessionId")))
                .sourceIp(text(record.get("sourceIp")))
                .userAgent(text(record.get("userAgent")))
                .description(text(record.get("description")))
                .build();
        if (record.get("metadata") instanceof Map<?, ?> metadata) {
            ((Map<String, Object>) metadata).forEach(event::addMetadata);
        }
        return event;
    }

    /** A value the record keeps as it is: text, a number, a truth value, or a list of them. */
    private static boolean plain(Object value) {
        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return true;
        }
        if (value instanceof Collection<?> values) {
            return values.stream().allMatch(item -> item instanceof String || item instanceof Number
                    || item instanceof Boolean);
        }
        return false;
    }

    private static String text(Object value) {
        return value != null ? value.toString() : null;
    }
}
