package io.contexa.contexaiam.security.core.metrics;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 세션 메트릭 추적 및 모니터링
 *
 * 세션 관련 이벤트와 통계를 추적하여 보안 분석과 성능 모니터링에 활용합니다.
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
public class SessionMetrics {

    // 세션 무효화 사유별 카운터
    private final Map<String, AtomicLong> invalidationReasonCounters = new ConcurrentHashMap<>();

    // 총 세션 카운터
    private final AtomicLong totalActiveSessions = new AtomicLong(0);
    private final AtomicLong totalInvalidatedSessions = new AtomicLong(0);
    private final AtomicLong totalCreatedSessions = new AtomicLong(0);

    // 세션 이벤트 타임스탬프
    private volatile long lastInvalidationTime = 0;
    private volatile long lastCreationTime = 0;

    /**
     * 세션 무효화 기록
     *
     * @param reason 무효화 사유
     */
    public void recordSessionInvalidation(String reason) {
        if (reason == null) {
            reason = "Unknown";
        }

        // 사유별 카운터 증가
        invalidationReasonCounters.computeIfAbsent(reason, k -> new AtomicLong(0))
                .incrementAndGet();

        // 총 무효화 카운터 증가
        totalInvalidatedSessions.incrementAndGet();

        // 활성 세션 감소
        totalActiveSessions.decrementAndGet();

        // 마지막 무효화 시간 업데이트
        lastInvalidationTime = System.currentTimeMillis();

        log.debug("Session invalidated - Reason: {}, Total invalidated: {}, Active sessions: {}",
                reason, totalInvalidatedSessions.get(), totalActiveSessions.get());
    }

    /**
     * 세션 생성 기록
     */
    public void recordSessionCreation() {
        totalCreatedSessions.incrementAndGet();
        totalActiveSessions.incrementAndGet();
        lastCreationTime = System.currentTimeMillis();

        log.debug("Session created - Total created: {}, Active sessions: {}",
                totalCreatedSessions.get(), totalActiveSessions.get());
    }

    /**
     * 세션 메트릭 조회
     *
     * @return 현재 메트릭 상태
     */
    public SessionMetricsSnapshot getSnapshot() {
        return SessionMetricsSnapshot.builder()
                .totalActiveSessions(totalActiveSessions.get())
                .totalInvalidatedSessions(totalInvalidatedSessions.get())
                .totalCreatedSessions(totalCreatedSessions.get())
                .invalidationReasonCounts(new ConcurrentHashMap<>(invalidationReasonCounters))
                .lastInvalidationTime(lastInvalidationTime)
                .lastCreationTime(lastCreationTime)
                .build();
    }

    /**
     * 메트릭 초기화
     */
    public void reset() {
        invalidationReasonCounters.clear();
        totalActiveSessions.set(0);
        totalInvalidatedSessions.set(0);
        totalCreatedSessions.set(0);
        lastInvalidationTime = 0;
        lastCreationTime = 0;

        log.info("Session metrics reset");
    }

    /**
     * 활성 세션 수 조회
     */
    public long getActiveSessions() {
        return totalActiveSessions.get();
    }

    /**
     * 무효화된 세션 수 조회
     */
    public long getInvalidatedSessions() {
        return totalInvalidatedSessions.get();
    }

    /**
     * 세션 메트릭 스냅샷
     */
    public static class SessionMetricsSnapshot {
        private final long totalActiveSessions;
        private final long totalInvalidatedSessions;
        private final long totalCreatedSessions;
        private final Map<String, AtomicLong> invalidationReasonCounts;
        private final long lastInvalidationTime;
        private final long lastCreationTime;

        private SessionMetricsSnapshot(Builder builder) {
            this.totalActiveSessions = builder.totalActiveSessions;
            this.totalInvalidatedSessions = builder.totalInvalidatedSessions;
            this.totalCreatedSessions = builder.totalCreatedSessions;
            this.invalidationReasonCounts = builder.invalidationReasonCounts;
            this.lastInvalidationTime = builder.lastInvalidationTime;
            this.lastCreationTime = builder.lastCreationTime;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private long totalActiveSessions;
            private long totalInvalidatedSessions;
            private long totalCreatedSessions;
            private Map<String, AtomicLong> invalidationReasonCounts;
            private long lastInvalidationTime;
            private long lastCreationTime;

            public Builder totalActiveSessions(long totalActiveSessions) {
                this.totalActiveSessions = totalActiveSessions;
                return this;
            }

            public Builder totalInvalidatedSessions(long totalInvalidatedSessions) {
                this.totalInvalidatedSessions = totalInvalidatedSessions;
                return this;
            }

            public Builder totalCreatedSessions(long totalCreatedSessions) {
                this.totalCreatedSessions = totalCreatedSessions;
                return this;
            }

            public Builder invalidationReasonCounts(Map<String, AtomicLong> invalidationReasonCounts) {
                this.invalidationReasonCounts = invalidationReasonCounts;
                return this;
            }

            public Builder lastInvalidationTime(long lastInvalidationTime) {
                this.lastInvalidationTime = lastInvalidationTime;
                return this;
            }

            public Builder lastCreationTime(long lastCreationTime) {
                this.lastCreationTime = lastCreationTime;
                return this;
            }

            public SessionMetricsSnapshot build() {
                return new SessionMetricsSnapshot(this);
            }
        }

        // Getters
        public long getTotalActiveSessions() {
            return totalActiveSessions;
        }

        public long getTotalInvalidatedSessions() {
            return totalInvalidatedSessions;
        }

        public long getTotalCreatedSessions() {
            return totalCreatedSessions;
        }

        public Map<String, AtomicLong> getInvalidationReasonCounts() {
            return invalidationReasonCounts;
        }

        public long getLastInvalidationTime() {
            return lastInvalidationTime;
        }

        public long getLastCreationTime() {
            return lastCreationTime;
        }
    }
}