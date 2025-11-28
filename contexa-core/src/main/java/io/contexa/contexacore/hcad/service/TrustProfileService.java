package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.hcad.domain.RiskLevel;
import io.contexa.contexacore.hcad.domain.SecurityIncident;
import io.contexa.contexacore.hcad.domain.UserTrustProfile;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
/**
 * 사용자 신뢰 프로필 관리 서비스
 *
 * ZeroTrustAdaptiveEngine에서 분리된 신뢰 프로필 관리 전담 서비스
 * - 프로필 생성/조회/업데이트
 * - Redis 영속성 관리
 * - 메모리 캐시 관리
 */
@Slf4j
@RequiredArgsConstructor
public class TrustProfileService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Map<String, UserTrustProfile> userTrustProfiles = new ConcurrentHashMap<>();

    private static final String REDIS_KEY_PREFIX = "zerotrust:profile:";
    private static final long REDIS_TTL_HOURS = 24;

    public UserTrustProfile getOrCreateUserTrustProfile(String userId) {
        return userTrustProfiles.computeIfAbsent(userId, this::loadOrCreateFromRedis);
    }

    private UserTrustProfile loadOrCreateFromRedis(String userId) {
        try {
            String profileKey = REDIS_KEY_PREFIX + userId;
            UserTrustProfile existingProfile = (UserTrustProfile) redisTemplate.opsForValue().get(profileKey);

            if (existingProfile != null) {
                log.debug("[TrustProfile] Loaded existing profile for user {}", userId);
                return existingProfile;
            }

            UserTrustProfile newProfile = createDefaultTrustProfile(userId);
            saveToRedis(newProfile);
            log.info("[TrustProfile] Created new profile for user {}", userId);
            return newProfile;

        } catch (Exception e) {
            log.error("[TrustProfile] Failed to load/create profile for user {}", userId, e);
            return createDefaultTrustProfile(userId);
        }
    }

    private UserTrustProfile createDefaultTrustProfile(String userId) {
        // Zero Trust 원칙: 신규 사용자는 낮은 신뢰도에서 시작 (Never Trust, Always Verify)
        return UserTrustProfile.builder()
            .userId(userId)
            .currentTrustScore(0.3)  // Zero Trust: 신규 사용자 기본값 0.5→0.3
            .baselineTrustScore(0.3)  // Zero Trust: 신규 사용자 기본값 0.5→0.3
            .riskLevel(RiskLevel.HIGH)  // 낮은 신뢰도에 맞는 위험 수준
            .profileCreatedAt(Instant.now())
            .lastUpdatedAt(Instant.now())
            .analysisCount(0L)
            .behaviorPatterns(new HashMap<>())
            .securityIncidents(new ArrayList<>())
            .adaptiveThresholds(new HashMap<>())
            .build();
    }

    public void updateTrustScore(UserTrustProfile profile, double newTrustScore) {
        profile.setCurrentTrustScore(newTrustScore);
        profile.setLastUpdatedAt(Instant.now());
        profile.setRiskLevel(calculateRiskLevel(newTrustScore));
        saveToRedis(profile);
        log.debug("[TrustProfile] Updated trust score for user {} to {}",
                 profile.getUserId(), String.format("%.3f", newTrustScore));
    }

    public void addSecurityIncident(UserTrustProfile profile, SecurityIncident incident) {
        profile.getSecurityIncidents().add(incident);
        profile.setLastUpdatedAt(Instant.now());
        saveToRedis(profile);
        log.warn("[TrustProfile] Added security incident for user {}: {}",
                profile.getUserId(), incident.getEventType());
    }

    public void updateBehaviorPattern(UserTrustProfile profile, String patternKey, Object patternValue) {
        profile.getBehaviorPatterns().put(patternKey, patternValue);
        profile.setLastUpdatedAt(Instant.now());
        saveToRedis(profile);
    }

    public void updateAdaptiveThreshold(UserTrustProfile profile, String thresholdKey, Double thresholdValue) {
        profile.getAdaptiveThresholds().put(thresholdKey, thresholdValue);
        profile.setLastUpdatedAt(Instant.now());
        saveToRedis(profile);
    }

    public void incrementAnalysisCount(UserTrustProfile profile) {
        profile.setAnalysisCount(profile.getAnalysisCount() + 1);
        profile.setLastUpdatedAt(Instant.now());
        if (profile.getAnalysisCount() % 100 == 0) {
            saveToRedis(profile);
        }
    }

    private void saveToRedis(UserTrustProfile profile) {
        try {
            String profileKey = REDIS_KEY_PREFIX + profile.getUserId();
            redisTemplate.opsForValue().set(profileKey, profile, REDIS_TTL_HOURS, TimeUnit.HOURS);
        } catch (Exception e) {
            log.error("[TrustProfile] Failed to save profile to Redis: userId={}", profile.getUserId(), e);
        }
    }

    private RiskLevel calculateRiskLevel(double trustScore) {
        if (trustScore >= 0.7) return RiskLevel.LOW;
        else if (trustScore >= 0.4) return RiskLevel.MEDIUM;
        else if (trustScore >= 0.2) return RiskLevel.HIGH;
        else return RiskLevel.CRITICAL;
    }

    public void resetProfile(String userId) {
        userTrustProfiles.remove(userId);
        String profileKey = REDIS_KEY_PREFIX + userId;
        redisTemplate.delete(profileKey);
        log.info("[TrustProfile] Reset profile for user {}", userId);
    }

    public void cleanupCache() {
        Instant threshold = Instant.now().minusSeconds(3600);
        userTrustProfiles.entrySet().removeIf(entry ->
            entry.getValue().getLastUpdatedAt().isBefore(threshold)
        );
        log.info("[TrustProfile] Cleaned up cache, remaining profiles: {}", userTrustProfiles.size());
    }
}
