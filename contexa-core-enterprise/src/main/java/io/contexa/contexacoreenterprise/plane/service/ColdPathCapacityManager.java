package io.contexa.contexacoreenterprise.plane.service;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.decision.EventTier;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Cold Path 용량 관리 시스템
 *
 * AI 분석 경로(Cold Path)의 용량을 관리하고, 과부하 시 우선순위 큐와
 * Graceful Degradation을 통해 시스템 안정성을 보장합니다.
 *
 * 핵심 기능:
 * 1. ModelTier 기반 우선순위 큐 (CRITICAL > HIGH > MEDIUM > LOW)
 * 2. 용량 초과 시 Graceful Degradation (낮은 우선순위 샘플링 감소)
 * 3. 실시간 용량 모니터링 및 통계
 *
 * 외부기관 1 피드백 반영:
 * - "Cold Path 용량 관리가 필요합니다"
 * - Priority Queue + Graceful Degradation
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
@Service
public class ColdPathCapacityManager {

    @Autowired
    @Qualifier("generalRedisTemplate")
    private RedisTemplate<String, Object> redisTemplate;

    // ===== 설정값 (application.yml에서 주입) =====

    /**
     * Cold Path 최대 큐 크기 (기본: 10,000)
     */
    @Value("${coldpath.capacity.max.queue.size:10000}")
    private int maxQueueSize;

    /**
     * Warning 임계값 (기본: 70%)
     * 이 비율 초과 시 경고 및 Degradation 시작
     */
    @Value("${coldpath.capacity.warning.threshold:0.7}")
    private double warningThreshold;

    /**
     * Critical 임계값 (기본: 90%)
     * 이 비율 초과 시 LOW/MEDIUM Tier 거부
     */
    @Value("${coldpath.capacity.critical.threshold:0.9}")
    private double criticalThreshold;

    /**
     * Degradation 시 샘플링 감소 비율 (기본: 0.5)
     * Warning 상태에서 LOW/MEDIUM Tier 샘플링을 50%로 감소
     */
    @Value("${coldpath.capacity.degradation.rate:0.5}")
    private double degradationRate;

    /**
     * 큐 만료 시간 (초, 기본: 300초 = 5분)
     * 이 시간 초과한 이벤트는 자동 제거
     */
    @Value("${coldpath.capacity.queue.expiration:300}")
    private int queueExpirationSeconds;

    // ===== 인메모리 우선순위 큐 =====

    /**
     * EventTier별 우선순위 큐
     * CRITICAL > HIGH > MEDIUM > LOW
     */
    private final Map<EventTier, PriorityBlockingQueue<QueuedEvent>> tierQueues = new ConcurrentHashMap<>();

    /**
     * 전체 큐 크기 (모든 Tier 합산)
     */
    private final java.util.concurrent.atomic.AtomicInteger totalQueueSize = new java.util.concurrent.atomic.AtomicInteger(0);

    // ===== Public Methods =====

    /**
     * Cold Path 이벤트 추가 시도
     *
     * @param event SecurityEvent
     * @param tier EventTier
     * @return EnqueueResult (성공 여부 및 거부 이유)
     */
    public EnqueueResult tryEnqueue(SecurityEvent event, EventTier tier) {
        // 1. 현재 용량 상태 확인
        CapacityStatus status = getCapacityStatus();

        // 2. Critical 상태에서 LOW/MEDIUM Tier 거부
        if (status == CapacityStatus.CRITICAL) {
            if (tier == EventTier.LOW || tier == EventTier.MEDIUM) {
                log.warn("[ColdPathCapacity] Rejecting {} tier event due to CRITICAL capacity: {}",
                        tier, event.getEventId());

                recordRejection(tier, "CRITICAL_CAPACITY");

                return EnqueueResult.rejected("CRITICAL_CAPACITY", status);
            }
        }

        // 3. Warning 상태에서 Degradation 적용
        if (status == CapacityStatus.WARNING) {
            if (tier == EventTier.LOW || tier == EventTier.MEDIUM) {
                // 50% 확률로 거부
                if (Math.random() > degradationRate) {
                    log.debug("[ColdPathCapacity] Degrading {} tier event: {}",
                            tier, event.getEventId());

                    recordRejection(tier, "DEGRADATION");

                    return EnqueueResult.rejected("DEGRADATION", status);
                }
            }
        }

        // 4. 큐에 추가
        PriorityBlockingQueue<QueuedEvent> queue = getOrCreateQueue(tier);

        QueuedEvent queuedEvent = QueuedEvent.builder()
                .event(event)
                .tier(tier)
                .enqueuedAt(LocalDateTime.now())
                .priority(getTierPriority(tier))
                .build();

        boolean added = queue.offer(queuedEvent);

        if (added) {
            int currentSize = totalQueueSize.incrementAndGet();

            log.debug("[ColdPathCapacity] Enqueued {} tier event: {} (queue size: {})",
                    tier, event.getEventId(), currentSize);

            recordEnqueue(tier);

            return EnqueueResult.success(status);
        } else {
            log.error("[ColdPathCapacity] Failed to enqueue {} tier event: {}",
                    tier, event.getEventId());

            recordRejection(tier, "QUEUE_FULL");

            return EnqueueResult.rejected("QUEUE_FULL", status);
        }
    }

    /**
     * Cold Path 이벤트 Dequeue (우선순위 순)
     *
     * @return QueuedEvent (없으면 null)
     */
    public QueuedEvent dequeue() {
        // CRITICAL > HIGH > MEDIUM > LOW 순으로 확인
        for (EventTier tier : EventTier.values()) {
            PriorityBlockingQueue<QueuedEvent> queue = tierQueues.get(tier);
            if (queue != null && !queue.isEmpty()) {
                QueuedEvent event = queue.poll();
                if (event != null) {
                    totalQueueSize.decrementAndGet();

                    // 만료된 이벤트 필터링
                    if (isExpired(event)) {
                        log.warn("[ColdPathCapacity] Dequeued expired event: {} (age: {}s)",
                                event.getEvent().getEventId(),
                                getAgeInSeconds(event));

                        recordExpiration(tier);
                        return dequeue(); // 다음 이벤트 시도
                    }

                    recordDequeue(tier);

                    return event;
                }
            }
        }

        return null;
    }

    /**
     * 현재 용량 상태 조회
     *
     * @return CapacityStatus (NORMAL/WARNING/CRITICAL)
     */
    public CapacityStatus getCapacityStatus() {
        double usage = getCurrentUsageRate();

        if (usage >= criticalThreshold) {
            return CapacityStatus.CRITICAL;
        } else if (usage >= warningThreshold) {
            return CapacityStatus.WARNING;
        } else {
            return CapacityStatus.NORMAL;
        }
    }

    /**
     * 현재 사용률 (0.0 ~ 1.0)
     */
    public double getCurrentUsageRate() {
        return (double) totalQueueSize.get() / maxQueueSize;
    }

    /**
     * 용량 통계 조회
     */
    public CapacityStats getCapacityStats() {
        Map<EventTier, Integer> queueSizes = new HashMap<>();
        for (EventTier tier : EventTier.values()) {
            PriorityBlockingQueue<QueuedEvent> queue = tierQueues.get(tier);
            queueSizes.put(tier, queue != null ? queue.size() : 0);
        }

        return CapacityStats.builder()
                .totalQueueSize(totalQueueSize.get())
                .maxQueueSize(maxQueueSize)
                .usageRate(getCurrentUsageRate())
                .capacityStatus(getCapacityStatus())
                .queueSizesByTier(queueSizes)
                .warningThreshold(warningThreshold)
                .criticalThreshold(criticalThreshold)
                .build();
    }

    /**
     * 만료된 이벤트 정리 (주기적 호출)
     */
    public int cleanupExpiredEvents() {
        int cleaned = 0;

        for (EventTier tier : EventTier.values()) {
            PriorityBlockingQueue<QueuedEvent> queue = tierQueues.get(tier);
            if (queue != null) {
                List<QueuedEvent> toRemove = new ArrayList<>();

                for (QueuedEvent event : queue) {
                    if (isExpired(event)) {
                        toRemove.add(event);
                    }
                }

                for (QueuedEvent event : toRemove) {
                    if (queue.remove(event)) {
                        totalQueueSize.decrementAndGet();
                        cleaned++;
                        recordExpiration(tier);
                    }
                }
            }
        }

        if (cleaned > 0) {
            log.info("[ColdPathCapacity] Cleaned up {} expired events", cleaned);
        }

        return cleaned;
    }

    // ===== Private Methods =====

    /**
     * Tier별 우선순위 반환
     * 낮을수록 높은 우선순위 (CRITICAL=1, LOW=4, BENIGN=5)
     */
    private int getTierPriority(EventTier tier) {
        switch (tier) {
            case CRITICAL:
                return 1;
            case HIGH:
                return 2;
            case MEDIUM:
                return 3;
            case LOW:
                return 4;
            case BENIGN:
                return 5;
            default:
                return 10;
        }
    }

    /**
     * Tier별 큐 생성 또는 조회
     */
    private PriorityBlockingQueue<QueuedEvent> getOrCreateQueue(EventTier tier) {
        return tierQueues.computeIfAbsent(tier, t ->
                new PriorityBlockingQueue<>(1000, Comparator.comparingInt(QueuedEvent::getPriority))
        );
    }

    /**
     * 이벤트 만료 여부 확인
     */
    private boolean isExpired(QueuedEvent event) {
        long ageInSeconds = getAgeInSeconds(event);
        return ageInSeconds > queueExpirationSeconds;
    }

    /**
     * 이벤트 나이 계산 (초)
     */
    private long getAgeInSeconds(QueuedEvent event) {
        return java.time.Duration.between(event.getEnqueuedAt(), LocalDateTime.now()).getSeconds();
    }

    // ===== 통계 기록 (Redis) =====

    /**
     * Enqueue 통계 기록
     */
    private void recordEnqueue(EventTier tier) {
        String key = "coldpath:stats:enqueue:" + tier.name();
        redisTemplate.opsForValue().increment(key, 1);
        redisTemplate.expire(key, 1, TimeUnit.HOURS);
    }

    /**
     * Dequeue 통계 기록
     */
    private void recordDequeue(EventTier tier) {
        String key = "coldpath:stats:dequeue:" + tier.name();
        redisTemplate.opsForValue().increment(key, 1);
        redisTemplate.expire(key, 1, TimeUnit.HOURS);
    }

    /**
     * Rejection 통계 기록
     */
    private void recordRejection(EventTier tier, String reason) {
        String key = "coldpath:stats:rejection:" + tier.name() + ":" + reason;
        redisTemplate.opsForValue().increment(key, 1);
        redisTemplate.expire(key, 1, TimeUnit.HOURS);
    }

    /**
     * Expiration 통계 기록
     */
    private void recordExpiration(EventTier tier) {
        String key = "coldpath:stats:expiration:" + tier.name();
        redisTemplate.opsForValue().increment(key, 1);
        redisTemplate.expire(key, 1, TimeUnit.HOURS);
    }

    // ===== Inner Classes =====

    /**
     * 큐에 저장되는 이벤트
     */
    @Getter
    @Builder
    public static class QueuedEvent {
        private final SecurityEvent event;
        private final EventTier tier;
        private final LocalDateTime enqueuedAt;
        private final int priority; // 낮을수록 높은 우선순위 (CRITICAL=1, LOW=4)
    }

    /**
     * Enqueue 결과
     */
    @Getter
    @Builder
    public static class EnqueueResult {
        private final boolean success;
        private final String rejectionReason; // null이면 성공
        private final CapacityStatus capacityStatus;

        public static EnqueueResult success(CapacityStatus status) {
            return EnqueueResult.builder()
                    .success(true)
                    .rejectionReason(null)
                    .capacityStatus(status)
                    .build();
        }

        public static EnqueueResult rejected(String reason, CapacityStatus status) {
            return EnqueueResult.builder()
                    .success(false)
                    .rejectionReason(reason)
                    .capacityStatus(status)
                    .build();
        }
    }

    /**
     * 용량 상태
     */
    public enum CapacityStatus {
        NORMAL,      // < 70%
        WARNING,     // 70% ~ 90%
        CRITICAL     // > 90%
    }

    /**
     * 용량 통계
     */
    @Getter
    @Builder
    public static class CapacityStats {
        private final int totalQueueSize;
        private final int maxQueueSize;
        private final double usageRate;
        private final CapacityStatus capacityStatus;
        private final Map<EventTier, Integer> queueSizesByTier;
        private final double warningThreshold;
        private final double criticalThreshold;
    }
}
