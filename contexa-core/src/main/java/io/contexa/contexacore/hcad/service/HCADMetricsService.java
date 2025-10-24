package io.contexa.contexacore.hcad.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * HCAD 메트릭 관리 서비스
 *
 * HCAD 필터의 성능 메트릭 수집 및 집계 담당:
 * - 샘플링 기반 메트릭 수집
 * - Redis 기반 집계 통계
 * - 응답 시간 히스토그램
 * - 이상 탐지 이벤트 기록
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HCADMetricsService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${hcad.threshold.warn:0.7}")
    private double warnThreshold;

    @Value("${hcad.metrics.slow-request-threshold-ms:30}")
    private long metricsSlowRequestThresholdMs;

    @Value("${hcad.metrics.sampling-rate:0.1}")
    private double metricsSamplingRate;

    /**
     * 메트릭 기록 (샘플링 최적화 버전)
     *
     * @param userId 사용자 ID
     * @param anomalyScore 이상 점수
     * @param processingTime 처리 시간 (ms)
     * @param wasBlocked 차단 여부
     */
    public void recordMetrics(String userId, double anomalyScore, long processingTime, boolean wasBlocked) {
        try {
            // 샘플링 기반 메트릭 수집 (기본 10% 샘플링)
            if (Math.random() > metricsSamplingRate && !wasBlocked && anomalyScore < warnThreshold) {
                return; // 정상 요청은 샘플링으로만 기록
            }

            // 중요한 이벤트는 항상 기록 (차단, 경고 임계값 이상)
            if (wasBlocked || anomalyScore >= warnThreshold || processingTime > metricsSlowRequestThresholdMs) {
                // 상세 메트릭 저장 (중요 이벤트만)
                String metricsKey = "hcad:metrics:critical:v2:" + userId + ":" + System.currentTimeMillis();
                redisTemplate.opsForValue().set(metricsKey,
                    String.format("score:%.3f,time:%d,blocked:%b", anomalyScore, processingTime, wasBlocked),
                    Duration.ofHours(24));
            }

            // 집계 메트릭은 항상 업데이트 (경량화)
            String statsKey = "hcad:stats:global:v2";
            redisTemplate.opsForHash().increment(statsKey, "total_requests", 1);

            if (wasBlocked) {
                redisTemplate.opsForHash().increment(statsKey, "blocked_requests", 1);
            } else if (anomalyScore >= warnThreshold) {
                redisTemplate.opsForHash().increment(statsKey, "warned_requests", 1);
            }

            if (processingTime > metricsSlowRequestThresholdMs) {
                redisTemplate.opsForHash().increment(statsKey, "slow_requests", 1);
            }

            // 응답 시간 히스토그램 - 샘플링된 요청만
            if (Math.random() <= metricsSamplingRate) {
                String histogramKey = "hcad:histogram:response_time";
                String bucket = getBucket(processingTime);
                redisTemplate.opsForHash().increment(histogramKey, bucket, 1);
            }

        } catch (Exception e) {
            log.debug("[HCAD] 메트릭 기록 실패", e);
        }
    }

    /**
     * 응답 시간 버킷 결정
     *
     * @param processingTime 처리 시간 (ms)
     * @return 버킷 이름
     */
    public String getBucket(long processingTime) {
        if (processingTime <= 5) return "0-5ms";
        else if (processingTime <= 10) return "6-10ms";
        else if (processingTime <= 20) return "11-20ms";
        else if (processingTime <= 30) return "21-30ms";
        else if (processingTime <= 50) return "31-50ms";
        else return "50ms+";
    }
}
