package io.contexa.contexacore.autonomous.event.monitoring;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.contexa.contexacore.properties.SecurityRedisProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class RedisMemoryMonitor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final MeterRegistry meterRegistry;
    private final SecurityRedisProperties securityRedisProperties;

    private final AtomicLong usedMemoryBytes = new AtomicLong(0);
    private final AtomicLong totalKeys = new AtomicLong(0);
    private final AtomicLong peakMemoryBytes = new AtomicLong(0);

    @PostConstruct
    public void initialize() {
        
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
            long max = monitor.securityRedisProperties.getMemory().getMaxMb() * 1024 * 1024;
            return max > 0 ? (double) used / max : 0.0;
        })
            .description("Redis memory utilization ratio (0-1)")
            .register(meterRegistry);

            }

    public void monitorMemory() {
        try {
            RedisMemoryInfo memoryInfo = getMemoryInfo();

            usedMemoryBytes.set(memoryInfo.getUsedMemory());
            totalKeys.set(memoryInfo.getTotalKeys());

            if (memoryInfo.getUsedMemory() > peakMemoryBytes.get()) {
                peakMemoryBytes.set(memoryInfo.getUsedMemory());
            }

            double utilizationRatio = (double) memoryInfo.getUsedMemory() / (securityRedisProperties.getMemory().getMaxMb() * 1024 * 1024);

            Map<String, Long> keysByPattern = analyzeKeyPatterns();

            checkThresholds(utilizationRatio, memoryInfo);

        } catch (Exception e) {
            log.error("Failed to monitor Redis memory", e);
        }
    }

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

    private Map<String, Long> analyzeKeyPatterns() {
        Map<String, Long> patternCounts = new HashMap<>();

        try {
            Set<String> keys = redisTemplate.keys("*");
            if (keys == null || keys.isEmpty()) {
                return patternCounts;
            }

            List<String> sampleKeys = keys.stream()
                .limit(100)
                .toList();

            for (String key : sampleKeys) {
                String pattern = extractPattern(key);
                patternCounts.merge(pattern, 1L, Long::sum);
            }

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

    private String extractPattern(String key) {
        if (key == null || key.isEmpty()) {
            return "UNKNOWN";
        }

        String[] parts = key.split(":");
        if (parts.length >= 3) {
            return parts[0] + ":" + parts[1] + ":" + parts[2];
        } else if (parts.length == 2) {
            return parts[0] + ":" + parts[1];
        } else {
            return parts[0];
        }
    }

    private void checkThresholds(double utilizationRatio, RedisMemoryInfo memoryInfo) {
        if (utilizationRatio >= securityRedisProperties.getMemory().getCriticalThreshold()) {
            log.error("CRITICAL: Redis memory usage at {:.1f}% (threshold: {:.1f}%)",
                utilizationRatio * 100, securityRedisProperties.getMemory().getCriticalThreshold() * 100);
            sendCriticalAlert(utilizationRatio, memoryInfo);

        } else if (utilizationRatio >= securityRedisProperties.getMemory().getWarningThreshold()) {
            log.warn("WARNING: Redis memory usage at {:.1f}% (threshold: {:.1f}%)",
                utilizationRatio * 100, securityRedisProperties.getMemory().getWarningThreshold() * 100);
            sendWarningAlert(utilizationRatio, memoryInfo);
        }

        if (memoryInfo.getEvictedKeys() > 0) {
            log.warn("Redis is evicting keys: evictedKeys={}", memoryInfo.getEvictedKeys());
        }

        if (memoryInfo.getFragmentationRatio() > 1.5) {
            log.warn("High memory fragmentation detected: ratio={:.2f}", memoryInfo.getFragmentationRatio());
        }
    }

    private void sendWarningAlert(double utilizationRatio, RedisMemoryInfo memoryInfo) {
        log.warn("ALERT: Redis memory warning - utilization={:.1f}%, keys={}, fragmentation={:.2f}",
            utilizationRatio * 100, memoryInfo.getTotalKeys(), memoryInfo.getFragmentationRatio());

    }

    private void sendCriticalAlert(double utilizationRatio, RedisMemoryInfo memoryInfo) {
        log.error("ALERT: Redis memory CRITICAL - utilization={:.1f}%, keys={}, evicted={}",
            utilizationRatio * 100, memoryInfo.getTotalKeys(), memoryInfo.getEvictedKeys());

    }

    public void cleanupExpiredKeys() {
        try {

            Set<String> keys = redisTemplate.keys("*");
            if (keys != null) {
                long cleaned = keys.stream()
                    .limit(1000)  
                    .filter(key -> {
                        Long ttl = redisTemplate.getExpire(key);
                        return ttl != null && ttl == -1;  
                    })
                        .peek(key -> log.debug("Cleaning key without TTL: {}", key))
                        .count();

                log.info("Cleanup completed: checked keys, found {} without TTL", cleaned);
            }

        } catch (Exception e) {
            log.error("Failed to cleanup expired keys", e);
        }
    }

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
