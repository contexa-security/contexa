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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Learns, once the user is verified, the request a restriction stopped (W5-2). When the engine enforces CHALLENGE,
 * ESCALATE or BLOCK on an analysed request, the request's facts are kept. When the user then passes the step-up the
 * decision asked for, or an administrator releases the block with ALLOW, those facts are learned: the baseline and the
 * past records learn the request's own path, resource, action, size and time, and the work profile adds the request as
 * an observation at a reduced weight. A request without kept facts is not learned here.
 */
@Slf4j
public class VerificationLearningService {

    /** The metadata of a learned request that names how its user was verified. */
    public static final String VERIFIED_BY = "verifiedBy";
    /** The metadata of a learned request that gives the weight it is learned at. */
    public static final String VERIFICATION_WEIGHT = "verificationWeight";
    static final String STEP_UP_REASONING = "Allowed after the user passed the step-up verification the decision "
            + "asked for; the request is learned at a reduced weight";
    private static final double DEFAULT_WEIGHT = 0.5;
    private static final Set<ZeroTrustAction> HELD = EnumSet.of(
            ZeroTrustAction.CHALLENGE, ZeroTrustAction.ESCALATE, ZeroTrustAction.BLOCK);

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final ProtectableWorkProfileCollector workProfileCollector;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private LearningPromotionService learningPromotionService;
    private volatile PastRecordQuery pastRecordQuery;

    public VerificationLearningService(SecurityContextDataStore dataStore,
                                       @Nullable SecurityLearningService securityLearningService,
                                       @Nullable ProtectableWorkProfileCollector workProfileCollector,
                                       @Nullable SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.dataStore = dataStore;
        this.securityLearningService = securityLearningService;
        this.workProfileCollector = workProfileCollector;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    /** Promotes the held requests whose values a step-up on a request with them vouches for (W5-1). */
    public void setLearningPromotionService(LearningPromotionService learningPromotionService) {
        this.learningPromotionService = learningPromotionService;
    }

    /** Where the outcome of a verification is written on the record of the decision it lifted (W5-4). */
    public void setPastRecordQuery(PastRecordQuery pastRecordQuery) {
        this.pastRecordQuery = pastRecordQuery;
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
            dataStore.holdVerificationLearning(event.getUserId().trim(), requestId, HeldRequestRecords.encode(event));
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
            recordOutcome(event, verification);
            event.addMetadata(VERIFIED_BY, verification != null ? verification.name() : null);
            event.addMetadata(VERIFICATION_WEIGHT, weight());
        });
        return held;
    }

    /**
     * Writes how the decision that stopped the request ended on its record (W5-4): verified by the step-up or released
     * by an administrator. The record is the one of the request's own event, whatever kind it was stored as. The
     * outcome is first kept by the event, so a record stored after this still takes it when it is stored.
     */
    private void recordOutcome(SecurityEvent event, Verification verification) {
        Object heldEventId = event.getMetadata() != null ? event.getMetadata().get(HeldRequestRecords.HELD_EVENT_ID) : null;
        if (verification == null || heldEventId == null) {
            return;
        }
        String outcome = verification == Verification.STEP_UP
                ? PastDeniedDecisions.VERIFIED_BY_STEP_UP : PastDeniedDecisions.RELEASED_BY_ADMINISTRATOR;
        if (dataStore != null) {
            try {
                dataStore.recordVerificationOutcome(heldEventId.toString(), outcome);
            } catch (RuntimeException e) {
                log.error("Failed to keep the outcome of a stopped request: userId={}", event.getUserId(), e);
            }
        }
        PastRecordQuery query = pastRecordQuery;
        if (query == null) {
            return;
        }
        try {
            for (String documentId : PastDeniedDecisions.documentIds(heldEventId.toString())) {
                query.recordOutcome(documentId, outcome);
            }
        } catch (RuntimeException e) {
            log.error("Failed to write the outcome of a stopped request on its record: userId={}", event.getUserId(), e);
        }
    }

    private Optional<SecurityEvent> takeHeld(String userId, String requestId) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(requestId) || dataStore == null) {
            return Optional.empty();
        }
        try {
            String record = dataStore.takeVerificationLearning(userId.trim(), requestId);
            return record == null ? Optional.empty() : Optional.of(HeldRequestRecords.decode(record, false));
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
        promoteVouched(userId.trim(), event);
        return true;
    }

    /** The step-up vouches for the identity values of the request it answered (W5-1). */
    private void promoteVouched(String userId, SecurityEvent event) {
        if (learningPromotionService == null || event.getMetadata() == null
                || !(event.getMetadata().get(HeldRequestRecords.IDENTITY_VALUES) instanceof Collection<?> values)
                || values.isEmpty()) {
            return;
        }
        try {
            learningPromotionService.promoteVerified(userId, values.stream().map(String::valueOf).toList());
        } catch (RuntimeException e) {
            log.error("Failed to promote held requests after a step-up: userId={}", userId, e);
        }
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
}
