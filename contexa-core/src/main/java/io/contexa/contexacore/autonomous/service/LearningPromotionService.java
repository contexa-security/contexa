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
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.context.support.VocabularyMigration;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

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

    /** docs/agent A3-4: how a promoted request is marked verified for the stored baseline. */
    static final String PROMOTED = "PROMOTED";
    static final String PROMOTED_REASONING = "Allowed earlier and learned once the first-seen values it held were seen "
            + "on other days or verified";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> RECORD = new TypeReference<>() {
    };
    /**
     * The promotion lock of a user's held requests (QF-28); apart from the baseline update lock, which the learning of
     * a promoted request takes inside it.
     */
    private static final String PROMOTION_LOCK_PREFIX = "learning:promotion:";
    /** Long enough for the learnings of several promoted requests, each of which may wait for the baseline lock. */
    private static final Duration LOCK_HOLD = Duration.ofSeconds(60);
    private static final Duration LOCK_WAIT = Duration.ofSeconds(5);
    private static final int LOCAL_LOCK_STRIPES = 64;

    private final SecurityContextDataStore dataStore;
    private final SecurityLearningService securityLearningService;
    private final ProtectableWorkProfileCollector workProfileCollector;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    /** The locks of this JVM when no lock service is set, striped so that their number stays fixed. */
    private final ReentrantLock[] localLocks = localLocks();
    private volatile DistributedLockService lockService;

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

    /** The lock service the promotions run under, user by user (QF-28); this JVM's own locks without one. */
    public void setLockService(@Nullable DistributedLockService lockService) {
        this.lockService = lockService;
    }

    /** Keeps a held request, then learns the user's held requests whose every value is now promotable. */
    public void hold(SecurityEvent event) {
        List<String> values = heldValues(event);
        String requestId = requestIdOf(event);
        if (values.isEmpty() || requestId == null || dataStore == null || !StringUtils.hasText(event.getUserId())) {
            return;
        }
        // docs/agent A3-7: an agent's held requests are kept and promoted apart from the person's; QF-29: and the held
        // requests of a user are kept within the request's tenant, as the user's baseline is.
        LearningSubject subject = LearningSubject.of(event);
        String userId = subject != null ? subject.tenantKey() : event.getUserId().trim();
        try {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("event", HeldRequestRecords.encode(event));
            record.put("values", values);
            record.put("day", dayOf(event).toString());
            record.put("vocabularyVersion", VocabularyVersion.CURRENT);
            dataStore.holdPromotionLearning(userId, requestId, JSON.writeValueAsString(record));
            promoteUnderLock(userId, Set.of());
        } catch (Exception e) {
            log.error("Failed to hold an allowed request for promotion: userId={}", userId, e);
        }
    }

    /** Learns the user's held requests whose values a verification on a request with them vouches for. */
    public void promoteVerified(String userId, Collection<String> values) {
        promoteVerified(null, userId, values);
    }

    /**
     * Learns the held requests of the user within the tenant whose values a verification on a request with them vouches
     * for (QF-29); the user alone without a tenant.
     */
    public void promoteVerified(@Nullable String tenantId, String userId, Collection<String> values) {
        if (!StringUtils.hasText(userId) || values == null || values.isEmpty() || dataStore == null
                || !settings().verifiedPromotes()) {
            return;
        }
        try {
            promoteUnderLock(BaselineDataStore.userKey(tenantId, ZeroTrustUserKey.person(userId.trim())),
                    Set.copyOf(values));
        } catch (Exception e) {
            log.error("Failed to promote held requests after a verification: userId={}", userId, e);
        }
    }

    /**
     * Promotes the user's held requests under the user's promotion lock (QF-28), so that two requests held at once do
     * not both read the held requests and learn them twice. A lock not taken in time leaves the requests held: the next
     * hold or verification of the user promotes them.
     */
    private void promoteUnderLock(String userId, Set<String> vouched) throws Exception {
        String key = PROMOTION_LOCK_PREFIX + userId;
        DistributedLockService locks = lockService;
        if (locks == null) {
            ReentrantLock local = localLocks[Math.floorMod(key.hashCode(), LOCAL_LOCK_STRIPES)];
            local.lock();
            try {
                promote(userId, vouched);
            } finally {
                local.unlock();
            }
            return;
        }
        String owner = UUID.randomUUID().toString();
        if (!locks.tryLockWithWait(key, owner, LOCK_HOLD, LOCK_WAIT)) {
            log.warn("Promotion lock not taken in time, the held requests wait for the next promotion: userId={}",
                    userId);
            return;
        }
        try {
            promote(userId, vouched);
        } finally {
            locks.unlock(key, owner);
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
        // docs/agent A3-4: a promoted value was seen on enough days or verified, so it never expires.
        if (event.getMetadata() == null || event.getMetadata().get(VerificationLearningService.VERIFIED_BY) == null) {
            event.addMetadata(VerificationLearningService.VERIFIED_BY, PROMOTED);
        }
        if (securityLearningService != null) {
            SecurityDecision decision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .confidence(0.95)
                    .riskScore(0.05)
                    .reasoning(PROMOTED_REASONING)
                    .analysisTime(System.currentTimeMillis())
                    .build();
            // The held event names its own user; the hold key may be an agent's (A3-7).
            securityLearningService.learnPromoted(StringUtils.hasText(event.getUserId()) ? event.getUserId().trim()
                    : userId, decision, event);
        }
        if (workProfileCollector != null) {
            workProfileCollector.recordVerified(event, 1.0);
        }
    }

    private List<String> heldValues(SecurityEvent event) {
        return LearningPromotionPolicy.heldValues(event, settings());
    }

    private static ReentrantLock[] localLocks() {
        ReentrantLock[] locks = new ReentrantLock[LOCAL_LOCK_STRIPES];
        for (int index = 0; index < locks.length; index++) {
            locks[index] = new ReentrantLock();
        }
        return locks;
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
