package io.contexa.contexacore.autonomous.event.monitoring;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Redis 메모리 모니터링 시스템
 *
 * 기능:
 * - 실시간 메모리 사용량 추적
 * - 키 개수 모니터링
 * - 경고 임계값 체크
 * - 메트릭 수집 및 알림
 */
@Slf4j
@RequiredArgsConstructor
public class RedisMemoryMonitor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final MeterRegistry meterRegistry;

    @Value("${security.redis.memory.max-mb:1024}")
    private long maxMemoryMb;

    @Value("${security.redis.memory.warning-threshold:0.8}")
    private double warningThreshold;

    @Value("${security.redis.memory.critical-threshold:0.9}")
    private double criticalThreshold;

    // Metrics
    private final AtomicLong usedMemoryBytes = new AtomicLong(0);
    private final AtomicLong totalKeys = new AtomicLong(0);
    private final AtomicLong peakMemoryBytes = new AtomicLong(0);

    @PostConstruct
    public void initialize() {
        // Metrics 등록
        Gauge.builder("redis.memory.used.bytes", usedMemoryBytes, AtomicLong::get)
            .description("Redis used memory in bytes")
            .register(meterRegistry);

        Gauge.builder("redis.memory.used.mb", usedMemoryBytes, val -> val.get() / 1024.0 / 1024.0)
            .description("Redis used memory in MB")
            .register(meterRegistry);

        Gauge.builder("redis.keys.total", totalKeys, AtomicLong::get)
            .description("Total number of keys in Redis")
            .register(meterRegistry);

        Gauge.builder("redis.memory.peak.bytes", peakMemoryBytes, AtomicLong::get)
            .description("Peak memory usage in bytes")
            .register(meterRegistry);

        Gauge.builder("redis.memory.utilization", this, monitor -> {
            long used = monitor.usedMemoryBytes.get();
            long max = monitor.maxMemoryMb * 1024 * 1024;
            return max > 0 ? (double) used / max : 0.0;
        })
            .description("Redis memory utilization ratio (0-1)")
            .register(meterRegistry);

        log.info("RedisMemoryMonitor initialized: maxMemoryMb={}, warningThreshold={}, criticalThreshold={}",
            maxMemoryMb, warningThreshold, criticalThreshold);
    }

    /**
     * 메모리 모니터링 (5분마다)
     */
//    @Scheduled(fixedRate = 300000)
    public void monitorMemory() {
        try {
            RedisMemoryInfo memoryInfo = getMemoryInfo();

            // Metrics 업데이트
            usedMemoryBytes.set(memoryInfo.getUsedMemory());
            totalKeys.set(memoryInfo.getTotalKeys());

            if (memoryInfo.getUsedMemory() > peakMemoryBytes.get()) {
                peakMemoryBytes.set(memoryInfo.getUsedMemory());
            }

            // 사용률 계산
            double utilizationRatio = (double) memoryInfo.getUsedMemory() / (maxMemoryMb * 1024 * 1024);

            log.info("=== Redis Memory Report ===");
            log.info("Used Memory: {}MB / {}MB ({:.1f}%)",
                memoryInfo.getUsedMemory() / 1024 / 1024,
                maxMemoryMb,
                utilizationRatio * 100);
            log.info("Total Keys: {}", memoryInfo.getTotalKeys());
            log.info("Peak Memory: {}MB", peakMemoryBytes.get() / 1024 / 1024);
            log.info("Fragmentation Ratio: {:.2f}", memoryInfo.getFragmentationRatio());
            log.info("Evicted Keys: {}", memoryInfo.getEvictedKeys());

            // 키 패턴 분석
            Map<String, Long> keysByPattern = analyzeKeyPatterns();
            log.info("Keys by pattern: {}", keysByPattern);

            // 임계값 체크
            checkThresholds(utilizationRatio, memoryInfo);

        } catch (Exception e) {
            log.error("Failed to monitor Redis memory", e);
        }
    }

    /**
     * Redis 메모리 정보 조회
     */
    private RedisMemoryInfo getMemoryInfo() {
        return redisTemplate.execute((RedisConnection connection) -> {
            Properties info = connection.info("memory");
            Properties stats = connection.info("stats");

            long usedMemory = Long.parseLong(info.getProperty("used_memory", "0"));
            long usedMemoryPeak = Long.parseLong(info.getProperty("used_memory_peak", "0"));
            double fragRatio = Double.parseDouble(info.getProperty("mem_fragmentation_ratio", "1.0"));
            long evictedKeys = Long.parseLong(stats.getProperty("evicted_keys", "0"));

            Long dbSize = connection.dbSize();

            return RedisMemoryInfo.builder()
                .usedMemory(usedMemory)
                .usedMemoryPeak(usedMemoryPeak)
                .fragmentationRatio(fragRatio)
                .evictedKeys(evictedKeys)
                .totalKeys(dbSize != null ? dbSize : 0L)
                .build();
        });
    }

    /**
     * 키 패턴별 분석
     */
    private Map<String, Long> analyzeKeyPatterns() {
        Map<String, Long> patternCounts = new HashMap<>();

        try {
            Set<String> keys = redisTemplate.keys("*");
            if (keys == null || keys.isEmpty()) {
                return patternCounts;
            }

            // 상위 100개만 샘플링 (성능 고려)
            List<String> sampleKeys = keys.stream()
                .limit(100)
                .toList();

            for (String key : sampleKeys) {
                String pattern = extractPattern(key);
                patternCounts.merge(pattern, 1L, Long::sum);
            }

            // 전체 키 수로 확장 (추정)
            long totalKeys = keys.size();
            long sampleSize = sampleKeys.size();
            if (sampleSize > 0) {
                double scaleFactor = (double) totalKeys / sampleSize;
                patternCounts.replaceAll((k, v) -> Math.round(v * scaleFactor));
            }

        } catch (Exception e) {
            log.warn("Failed to analyze key patterns", e);
        }

        return patternCounts;
    }

    /**
     * 키에서 패턴 추출
     */
    private String extractPattern(String key) {
        if (key == null || key.isEmpty()) {
            return "UNKNOWN";
        }

        // "security:auth:denied:*:*" → "security:auth:denied"
        String[] parts = key.split(":");
        if (parts.length >= 3) {
            return parts[0] + ":" + parts[1] + ":" + parts[2];
        } else if (parts.length == 2) {
            return parts[0] + ":" + parts[1];
        } else {
            return parts[0];
        }
    }

    /**
     * 임계값 체크 및 알림
     */
    private void checkThresholds(double utilizationRatio, RedisMemoryInfo memoryInfo) {
        if (utilizationRatio >= criticalThreshold) {
            log.error("CRITICAL: Redis memory usage at {:.1f}% (threshold: {:.1f}%)",
                utilizationRatio * 100, criticalThreshold * 100);
            sendCriticalAlert(utilizationRatio, memoryInfo);

        } else if (utilizationRatio >= warningThreshold) {
            log.warn("WARNING: Redis memory usage at {:.1f}% (threshold: {:.1f}%)",
                utilizationRatio * 100, warningThreshold * 100);
            sendWarningAlert(utilizationRatio, memoryInfo);
        }

        // Eviction 발생 시 경고
        if (memoryInfo.getEvictedKeys() > 0) {
            log.warn("Redis is evicting keys: evictedKeys={}", memoryInfo.getEvictedKeys());
        }

        // Fragmentation 높을 시 경고
        if (memoryInfo.getFragmentationRatio() > 1.5) {
            log.warn("High memory fragmentation detected: ratio={:.2f}", memoryInfo.getFragmentationRatio());
        }
    }

    /**
     * 경고 알림
     */
    private void sendWarningAlert(double utilizationRatio, RedisMemoryInfo memoryInfo) {
        log.warn("ALERT: Redis memory warning - utilization={:.1f}%, keys={}, fragmentation={:.2f}",
            utilizationRatio * 100, memoryInfo.getTotalKeys(), memoryInfo.getFragmentationRatio());

        // TODO: Slack, Email 등 실제 알림 구현
    }

    /**
     * 심각 알림
     */
    private void sendCriticalAlert(double utilizationRatio, RedisMemoryInfo memoryInfo) {
        log.error("ALERT: Redis memory CRITICAL - utilization={:.1f}%, keys={}, evicted={}",
            utilizationRatio * 100, memoryInfo.getTotalKeys(), memoryInfo.getEvictedKeys());

        // TODO: PagerDuty 등 긴급 알림 구현
    }

    /**
     * 수동 메모리 정리 (선택적)
     */
    public void cleanupExpiredKeys() {
        try {
            log.info("Starting Redis expired keys cleanup");

            // 샘플링으로 만료된 키 정리
            Set<String> keys = redisTemplate.keys("*");
            if (keys != null) {
                long cleaned = keys.stream()
                    .limit(1000)  // 최대 1000개
                    .filter(key -> {
                        Long ttl = redisTemplate.getExpire(key);
                        return ttl != null && ttl == -1;  // TTL 없는 키
                    })
                    .peek(key -> log.debug("Cleaning key without TTL: {}", key))
                    .count();

                log.info("Cleanup completed: checked keys, found {} without TTL", cleaned);
            }

        } catch (Exception e) {
            log.error("Failed to cleanup expired keys", e);
        }
    }

    /**
     * Redis 메모리 정보 모델
     */
    @lombok.Data
    @lombok.Builder
    private static class RedisMemoryInfo {
        private long usedMemory;
        private long usedMemoryPeak;
        private double fragmentationRatio;
        private long evictedKeys;
        private long totalKeys;
    }
}
