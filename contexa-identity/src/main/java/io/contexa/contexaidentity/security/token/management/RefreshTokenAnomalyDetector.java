package io.contexa.contexaidentity.security.token.management;

import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;


@Slf4j
@RequiredArgsConstructor
public class RefreshTokenAnomalyDetector {

    private static final String USER_ACTIVITY_PREFIX = "anomaly:activity:";
    private static final String LOCATION_HISTORY_PREFIX = "anomaly:location:";
    private static final String DEVICE_HISTORY_PREFIX = "anomaly:device:";

    
    private static final int RAPID_REFRESH_THRESHOLD = 3; 
    private static final Duration RAPID_REFRESH_WINDOW = Duration.ofMinutes(5);
    private static final double MAX_TRAVEL_SPEED_KM_H = 1000; 
    private static final double HIGH_RISK_THRESHOLD = 0.8;
    private static final double MEDIUM_RISK_THRESHOLD = 0.5;

    private final StringRedisTemplate redisTemplate;
    private final RedisEventPublisher redisEventPublisher;

    
    public AnomalyDetectionResult detectAnomaly(String username, String deviceId, ClientInfo clientInfo) {
        List<AnomalyCheckResult> checks = new ArrayList<>();

        
        checks.add(checkRapidRefresh(username, deviceId));

        
        checks.add(checkDeviceMismatch(username, deviceId, clientInfo));

        
        checks.add(checkConcurrentUsage(username, deviceId));

        
        checks.add(checkTimePatternAnomaly(username, clientInfo));

        
        return evaluateAnomalies(checks);
    }

    
    private AnomalyCheckResult checkRapidRefresh(String username, String deviceId) {
        String key = USER_ACTIVITY_PREFIX + username + ":" + deviceId + ":refresh";

        
        Long refreshCount = redisTemplate.opsForZSet().count(
                key,
                System.currentTimeMillis() - RAPID_REFRESH_WINDOW.toMillis(),
                System.currentTimeMillis()
        );

        if (refreshCount != null && refreshCount >= RAPID_REFRESH_THRESHOLD) {
            return new AnomalyCheckResult(
                    AnomalyType.RAPID_REFRESH,
                    0.8,
                    String.format("Rapid token refresh detected: %d times in %d minutes",
                            refreshCount, RAPID_REFRESH_WINDOW.toMinutes())
            );
        }

        
        redisTemplate.opsForZSet().add(key, UUID.randomUUID().toString(), System.currentTimeMillis());
        redisTemplate.expire(key, 1, TimeUnit.HOURS);

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "Normal refresh rate");
    }


    
    private AnomalyCheckResult checkDeviceMismatch(String username, String deviceId, ClientInfo clientInfo) {
        String key = DEVICE_HISTORY_PREFIX + username + ":" + deviceId;

        
        Set<String> fingerprints = redisTemplate.opsForSet().members(key);

        if (fingerprints != null && !fingerprints.isEmpty()) {
            if (!fingerprints.contains(clientInfo.deviceFingerprint())) {
                
                if (fingerprints.size() >= 3) {
                    return new AnomalyCheckResult(
                            AnomalyType.DEVICE_MISMATCH,
                            0.7,
                            "Multiple device fingerprints detected for same device ID"
                    );
                }
            }
        }

        
        redisTemplate.opsForSet().add(key, clientInfo.deviceFingerprint());
        redisTemplate.expire(key, 30, TimeUnit.DAYS);

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "Device fingerprint matches");
    }

    
    private AnomalyCheckResult checkConcurrentUsage(String username, String deviceId) {
        String pattern = USER_ACTIVITY_PREFIX + username + ":*:active";
        Set<String> activeDevices = redisTemplate.keys(pattern);

        if (activeDevices.size() > 1) {
            
            List<String> otherDevices = activeDevices.stream()
                    .filter(key -> !key.contains(deviceId))
                    .toList();

            if (!otherDevices.isEmpty()) {
                return new AnomalyCheckResult(
                        AnomalyType.SUSPICIOUS_PATTERN,
                        0.6,
                        String.format("Concurrent activity detected on %d devices", otherDevices.size())
                );
            }
        }

        
        String activeKey = USER_ACTIVITY_PREFIX + username + ":" + deviceId + ":active";
        redisTemplate.opsForValue().set(activeKey, "1", Duration.ofMinutes(15));

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "No concurrent usage detected");
    }

    
    private AnomalyCheckResult checkTimePatternAnomaly(String username, ClientInfo clientInfo) {
        
        String patternKey = USER_ACTIVITY_PREFIX + username + ":time_pattern";

        int currentHour = Instant.now().atZone(java.time.ZoneId.systemDefault()).getHour();

        
        String hourCount = (String) redisTemplate.opsForHash().get(patternKey, String.valueOf(currentHour));

        if (hourCount == null || Integer.parseInt(hourCount) < 5) {
            
            return new AnomalyCheckResult(
                    AnomalyType.SUSPICIOUS_PATTERN,
                    0.4,
                    String.format("Unusual activity time: %02d:00", currentHour)
            );
        }

        
        redisTemplate.opsForHash().increment(patternKey, String.valueOf(currentHour), 1);

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "Normal activity time");
    }

    
    private AnomalyDetectionResult evaluateAnomalies(List<AnomalyCheckResult> checks) {
        double maxRiskScore = checks.stream()
                .mapToDouble(AnomalyCheckResult::riskScore)
                .max()
                .orElse(0.0);

        AnomalyCheckResult highestRisk = checks.stream()
                .max(Comparator.comparing(AnomalyCheckResult::riskScore))
                .orElse(new AnomalyCheckResult(AnomalyType.NONE, 0.0, "No anomalies detected"));

        
        double combinedRisk = calculateCombinedRisk(checks);

        if (combinedRisk >= HIGH_RISK_THRESHOLD) {
            
            publishHighRiskEvent(highestRisk);
        }

        return new AnomalyDetectionResult(
                combinedRisk > MEDIUM_RISK_THRESHOLD,
                highestRisk.type(),
                highestRisk.description(),
                combinedRisk
        );
    }

    
    private double calculateCombinedRisk(List<AnomalyCheckResult> checks) {
        
        double weightedSum = 0.0;
        double weightTotal = 0.0;

        for (AnomalyCheckResult check : checks) {
            if (check.type() != AnomalyType.NONE) {
                double weight = getWeight(check.type());
                weightedSum += check.riskScore() * weight;
                weightTotal += weight;
            }
        }

        return weightTotal > 0 ? weightedSum / weightTotal : 0.0;
    }

    
    private double getWeight(AnomalyType type) {
        return switch (type) {
            case REUSED_TOKEN -> 1.0;        
            case GEOGRAPHIC_ANOMALY -> 0.9;    
            case RAPID_REFRESH -> 0.8;         
            case DEVICE_MISMATCH -> 0.7;       
            case SUSPICIOUS_PATTERN -> 0.5;    
            default -> 0.0;
        };
    }

    
    private void publishHighRiskEvent(AnomalyCheckResult risk) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("anomalyType", risk.type().name());
        eventData.put("riskScore", risk.riskScore());
        eventData.put("description", risk.description());
        eventData.put("timestamp", Instant.now().toString());

        redisEventPublisher.publishSecurityEvent("HIGH_RISK_ANOMALY_DETECTED",
                "system", "0.0.0.0", eventData);
    }

    

    private record AnomalyCheckResult(
            AnomalyType type,
            double riskScore,
            String description
    ) {}

    
    public interface GeoLocationService {
        double calculateDistance(String location1, String location2);
    }
}