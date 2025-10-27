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

/**
 * 리프레시 토큰 비정상 패턴 감지 서비스
 *
 * 다음과 같은 비정상 패턴을 감지:
 * - 짧은 시간 내 반복적인 토큰 갱신
 * - 지리적으로 불가능한 위치 이동
 * - 디바이스 핑거프린트 불일치
 * - 동시 다중 사용
 * - 비정상적인 사용 패턴
 *
 * @since 2024.12
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenAnomalyDetector {

    private static final String USER_ACTIVITY_PREFIX = "anomaly:activity:";
    private static final String LOCATION_HISTORY_PREFIX = "anomaly:location:";
    private static final String DEVICE_HISTORY_PREFIX = "anomaly:device:";

    // 임계값 설정
    private static final int RAPID_REFRESH_THRESHOLD = 3; // 5분 내 3회 이상
    private static final Duration RAPID_REFRESH_WINDOW = Duration.ofMinutes(5);
    private static final double MAX_TRAVEL_SPEED_KM_H = 1000; // 시속 1000km (비행기 속도)
    private static final double HIGH_RISK_THRESHOLD = 0.8;
    private static final double MEDIUM_RISK_THRESHOLD = 0.5;

    private final StringRedisTemplate redisTemplate;
    private final RedisEventPublisher eventPublisher;

    /**
     * 비정상 패턴 감지
     */
    public AnomalyDetectionResult detectAnomaly(String username, String deviceId, ClientInfo clientInfo) {
        List<AnomalyCheckResult> checks = new ArrayList<>();

        // 1. 급격한 토큰 갱신 감지
        checks.add(checkRapidRefresh(username, deviceId));

        // 2. 디바이스 불일치 감지
        checks.add(checkDeviceMismatch(username, deviceId, clientInfo));

        // 3. 동시 사용 감지
        checks.add(checkConcurrentUsage(username, deviceId));

        // 4. 시간대 패턴 이상 감지
        checks.add(checkTimePatternAnomaly(username, clientInfo));

        // 종합 평가
        return evaluateAnomalies(checks);
    }

    /**
     * 급격한 토큰 갱신 감지
     */
    private AnomalyCheckResult checkRapidRefresh(String username, String deviceId) {
        String key = USER_ACTIVITY_PREFIX + username + ":" + deviceId + ":refresh";

        // 최근 갱신 횟수 조회
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

        // 현재 갱신 기록
        redisTemplate.opsForZSet().add(key, UUID.randomUUID().toString(), System.currentTimeMillis());
        redisTemplate.expire(key, 1, TimeUnit.HOURS);

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "Normal refresh rate");
    }


    /**
     * 디바이스 불일치 감지
     */
    private AnomalyCheckResult checkDeviceMismatch(String username, String deviceId, ClientInfo clientInfo) {
        String key = DEVICE_HISTORY_PREFIX + username + ":" + deviceId;

        // 디바이스 핑거프린트 이력 조회
        Set<String> fingerprints = redisTemplate.opsForSet().members(key);

        if (fingerprints != null && !fingerprints.isEmpty()) {
            if (!fingerprints.contains(clientInfo.deviceFingerprint())) {
                // 새로운 핑거프린트 감지
                if (fingerprints.size() >= 3) {
                    return new AnomalyCheckResult(
                            AnomalyType.DEVICE_MISMATCH,
                            0.7,
                            "Multiple device fingerprints detected for same device ID"
                    );
                }
            }
        }

        // 현재 핑거프린트 저장
        redisTemplate.opsForSet().add(key, clientInfo.deviceFingerprint());
        redisTemplate.expire(key, 30, TimeUnit.DAYS);

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "Device fingerprint matches");
    }

    /**
     * 동시 사용 감지
     */
    private AnomalyCheckResult checkConcurrentUsage(String username, String deviceId) {
        String pattern = USER_ACTIVITY_PREFIX + username + ":*:active";
        Set<String> activeDevices = redisTemplate.keys(pattern);

        if (activeDevices.size() > 1) {
            // 다른 디바이스에서 동시 활동 감지
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

        // 현재 디바이스 활동 표시
        String activeKey = USER_ACTIVITY_PREFIX + username + ":" + deviceId + ":active";
        redisTemplate.opsForValue().set(activeKey, "1", Duration.ofMinutes(15));

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "No concurrent usage detected");
    }

    /**
     * 시간대 패턴 이상 감지
     */
    private AnomalyCheckResult checkTimePatternAnomaly(String username, ClientInfo clientInfo) {
        // 사용자의 일반적인 활동 시간대 분석
        String patternKey = USER_ACTIVITY_PREFIX + username + ":time_pattern";

        int currentHour = Instant.now().atZone(java.time.ZoneId.systemDefault()).getHour();

        // 시간대별 활동 빈도 조회
        String hourCount = (String) redisTemplate.opsForHash().get(patternKey, String.valueOf(currentHour));

        if (hourCount == null || Integer.parseInt(hourCount) < 5) {
            // 평소 활동하지 않는 시간대
            return new AnomalyCheckResult(
                    AnomalyType.SUSPICIOUS_PATTERN,
                    0.4,
                    String.format("Unusual activity time: %02d:00", currentHour)
            );
        }

        // 활동 시간 기록
        redisTemplate.opsForHash().increment(patternKey, String.valueOf(currentHour), 1);

        return new AnomalyCheckResult(AnomalyType.NONE, 0.0, "Normal activity time");
    }

    /**
     * 종합 평가
     */
    private AnomalyDetectionResult evaluateAnomalies(List<AnomalyCheckResult> checks) {
        double maxRiskScore = checks.stream()
                .mapToDouble(AnomalyCheckResult::riskScore)
                .max()
                .orElse(0.0);

        AnomalyCheckResult highestRisk = checks.stream()
                .max(Comparator.comparing(AnomalyCheckResult::riskScore))
                .orElse(new AnomalyCheckResult(AnomalyType.NONE, 0.0, "No anomalies detected"));

        // 복합 위험도 계산
        double combinedRisk = calculateCombinedRisk(checks);

        if (combinedRisk >= HIGH_RISK_THRESHOLD) {
            // 고위험 이벤트 발행
            publishHighRiskEvent(highestRisk);
        }

        return new AnomalyDetectionResult(
                combinedRisk > MEDIUM_RISK_THRESHOLD,
                highestRisk.type(),
                highestRisk.description(),
                combinedRisk
        );
    }

    /**
     * 복합 위험도 계산
     */
    private double calculateCombinedRisk(List<AnomalyCheckResult> checks) {
        // 가중 평균 계산
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

    /**
     * 이상 유형별 가중치
     */
    private double getWeight(AnomalyType type) {
        return switch (type) {
            case REUSED_TOKEN -> 1.0;        // 최고 위험
            case GEOGRAPHIC_ANOMALY -> 0.9;    // 높은 위험
            case RAPID_REFRESH -> 0.8;         // 높은 위험
            case DEVICE_MISMATCH -> 0.7;       // 중간 위험
            case SUSPICIOUS_PATTERN -> 0.5;    // 낮은 위험
            default -> 0.0;
        };
    }

    /**
     * 고위험 이벤트 발행
     */
    private void publishHighRiskEvent(AnomalyCheckResult risk) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("anomalyType", risk.type().name());
        eventData.put("riskScore", risk.riskScore());
        eventData.put("description", risk.description());
        eventData.put("timestamp", Instant.now().toString());

        eventPublisher.publishSecurityEvent("HIGH_RISK_ANOMALY_DETECTED",
                "system", "0.0.0.0", eventData);
    }

    // ===== 내부 클래스 =====

    private record AnomalyCheckResult(
            AnomalyType type,
            double riskScore,
            String description
    ) {}

    /**
     * 지리적 위치 서비스 (인터페이스)
     */
    public interface GeoLocationService {
        double calculateDistance(String location1, String location2);
    }
}