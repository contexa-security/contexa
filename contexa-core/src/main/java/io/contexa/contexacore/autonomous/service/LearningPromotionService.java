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
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.context.support.VocabularyMigration;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Holds back and later promotes the allowed requests whose first-seen values may not become usual at once (W5-1, plan
 * L1). A request {@link LearningPromotionPolicy} holds is not learned when it is allowed: its facts and the values it
 * held are kept, and its past record is marked held so that it is not retrieved. It is learned from its own facts (the
 * baseline, its past record under its own event id, the work profile at full weight) once every value it held is
 * promotable: held on enough different company days, or vouched for by a verification on a request with the value.
 * A request that still holds an unpromoted value keeps waiting; a kept request expires with the store's time limit.
 */
@Slf4j
public class LearningPromotionService {

    static final String PROMOTED_REASONING = "Allowed earlier and learned once the first-seen values it held were seen "
            + "on other days or verified";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> RECORD = new TypeReference<>() {
    };

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final ProtectableWorkProfileCollector workProfileCollector;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    public LearningPromotionService(SecurityContextDataStore dataStore,
                                    @Nullable SecurityLearningService securityLearningService,
                                    @Nullable ProtectableWorkProfileCollector workProfileCollector,
                                    @Nullable SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.dataStore = dataStore;
        this.securityLearningService = securityLearningService;
        this.workProfileCollector = workProfileCollector;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    /**
     * Whether the allowed request waits for promotion; if so the event is marked held, so that what records the
     * request as usual behaviour when it is committed (the work profile) leaves it out.
     */
    public boolean holds(SecurityEvent event) {
        if (event == null || heldValues(event).isEmpty()) {
            return false;
        }
        event.addMetadata(VectorDocumentMetadata.LEARNING_STATE, VectorDocumentMetadata.LEARNING_STATE_HELD);
        return true;
    }

    /** Keeps a held request, then learns the user's held requests whose every value is now promotable. */
    public void hold(SecurityEvent event) {
        List<String> values = heldValues(event);
        String requestId = requestIdOf(event);
        if (values.isEmpty() || requestId == null || dataStore == null || !StringUtils.hasText(event.getUserId())) {
            return;
        }
        String userId = event.getUserId().trim();
        try {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("event", HeldRequestRecords.encode(event));
            record.put("values", values);
            record.put("day", dayOf(event).toString());
            record.put("vocabularyVersion", VocabularyVersion.CURRENT);
            dataStore.holdPromotionLearning(userId, requestId, JSON.writeValueAsString(record));
            promote(userId, Set.of());
        } catch (Exception e) {
            log.error("Failed to hold an allowed request for promotion: userId={}", userId, e);
        }
    }

    /** Learns the user's held requests whose values a verification on a request with them vouches for. */
    public void promoteVerified(String userId, Collection<String> values) {
        if (!StringUtils.hasText(userId) || values == null || values.isEmpty() || dataStore == null
                || !settings().verifiedPromotes()) {
            return;
        }
        try {
            promote(userId.trim(), Set.copyOf(values));
        } catch (Exception e) {
            log.error("Failed to promote held requests after a verification: userId={}", userId, e);
        }
    }

    private void promote(String userId, Set<String> vouched) throws Exception {
        List<Held> held = new ArrayList<>();
        for (Map.Entry<String, String> entry : dataStore.promotionLearning(userId).entrySet()) {
            held.add(Held.read(entry.getKey(), entry.getValue()));
        }
        LearningPromotionPolicy.Settings settings = settings();
        Map<String, Set<LocalDate>> days = new HashMap<>();
        Map<String, Integer> observations = new HashMap<>();
        for (Held request : held) {
            for (String value : request.values()) {
                days.computeIfAbsent(value, key -> new HashSet<>()).add(request.day());
                observations.merge(value, 1, Integer::sum);
            }
        }
        Set<String> promotable = new HashSet<>(vouched);
        days.forEach((value, seen) -> {
            if (seen.size() >= settings.minDistinctDays() && observations.get(value) >= settings.minObservations()) {
                promotable.add(value);
            }
        });
        List<String> learned = new ArrayList<>();
        for (Held request : held) {
            if (!request.values().isEmpty() && promotable.containsAll(request.values())) {
                learn(userId, request);
                learned.add(request.requestId());
            }
        }
        dataStore.removePromotionLearning(userId, learned);
    }

    private void learn(String userId, Held request) throws Exception {
        SecurityEvent event = HeldRequestRecords.decode(request.event(), true);
        if (securityLearningService != null) {
            SecurityDecision decision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .confidence(0.95)
                    .riskScore(0.05)
                    .reasoning(PROMOTED_REASONING)
                    .analysisTime(System.currentTimeMillis())
                    .build();
            securityLearningService.learnPromoted(userId, decision, event);
        }
        if (workProfileCollector != null) {
            workProfileCollector.recordVerified(event, 1.0);
        }
    }

    private List<String> heldValues(SecurityEvent event) {
        return LearningPromotionPolicy.heldDifferences(event, settings()).stream()
                .map(LearningPromotionPolicy::valueOf)
                .distinct()
                .toList();
    }

    private LearningPromotionPolicy.Settings settings() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getBaseline() == null
                || securityZeroTrustProperties.getBaseline().getPromotion() == null) {
            return LearningPromotionPolicy.Settings.DEFAULTS;
        }
        return securityZeroTrustProperties.getBaseline().getPromotion().toPolicy();
    }

    /** The company day of the request; the day it is held on when the request has no time. */
    private static LocalDate dayOf(SecurityEvent event) {
        return event.getTimestamp() != null ? EventTimeZone.toLocal(event.getTimestamp()).toLocalDate()
                : LocalDate.now(EventTimeZone.get());
    }

    private static String requestIdOf(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
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

    /** A kept request: its facts, the values it held and the company day it was held on. */
    /** A held value of another vocabulary in today's form (W5-7): a network reads as today's band. */
    private static String inTodaysVocabulary(String value) {
        String prefix = DeviationDimension.NETWORK.name() + "=";
        if (!value.startsWith(prefix)) {
            return value;
        }
        String network = VocabularyMigration.network(value.substring(prefix.length()));
        return network != null ? prefix + network : value;
    }

    private record Held(String requestId, String event, List<String> values, LocalDate day) {

        static Held read(String requestId, String text) throws Exception {
            Map<String, Object> record = JSON.readValue(text, RECORD);
            List<String> values = new ArrayList<>();
            boolean current = VocabularyVersion.isCurrent(record.get("vocabularyVersion") != null
                    ? String.valueOf(record.get("vocabularyVersion")) : null);
            if (record.get("values") instanceof Collection<?> held) {
                held.forEach(value -> values.add(current ? String.valueOf(value) : inTodaysVocabulary(String.valueOf(value))));
            }
            return new Held(requestId, String.valueOf(record.get("event")), values,
                    LocalDate.parse(String.valueOf(record.get("day"))));
        }
    }
}
