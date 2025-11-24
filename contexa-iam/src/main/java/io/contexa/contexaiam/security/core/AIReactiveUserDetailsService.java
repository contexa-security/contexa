package io.contexa.contexaiam.security.core;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.exception.AnomalyDetectedException;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * AI-Native Reactive UserDetailsService
 * 
 * Redis에서 실시간 trust_score를 조회하여 Trust Tier 기반으로 
 * 사용자 권한을 동적으로 조정하는 UserDetailsService 구현체입니다.
 * 
 * Trust Tier System:
 * - Tier 1 (0.8-1.0): 모든 권한 부여
 * - Tier 2 (0.6-0.8): 민감한 작업 제외
 * - Tier 3 (0.4-0.6): 읽기 전용 권한
 * - Tier 4 (0.0-0.4): 최소 권한만 부여
 */
@Slf4j
@RequiredArgsConstructor
public class AIReactiveUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private final UnifiedNotificationService notificationService;
    private final AuditLogRepository auditLogRepository;
    
    @Value("${security.trust.tier.enabled:true}")
    private boolean trustTierEnabled;
    
    @Value("${security.trust.tier.cache.ttl:300}")
    private long trustScoreCacheTtl; // 초 단위
    
    @Value("${security.trust.tier.default.score:0.5}")
    private double defaultTrustScore;
    
    // Trust Tier 임계값
    @Value("${security.trust.tier.tier1.threshold:0.8}")
    private double tier1Threshold;
    
    @Value("${security.trust.tier.tier2.threshold:0.6}")
    private double tier2Threshold;
    
    @Value("${security.trust.tier.tier3.threshold:0.4}")
    private double tier3Threshold;
    
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. DB 에서 사용자 정보 조회
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        // 2. 기본 UserDetails 생성
        CustomUserDetails userDetails = new CustomUserDetails(user);
        
        // 3. Trust Tier가 활성화된 경우 권한 조정
       /* if (trustTierEnabled) {
            adjustAuthoritiesByTrustTier(userDetails, user);
        }*/
        
        return userDetails;
    }
    
    /**
     * Trust Tier에 따라 권한을 동적으로 조정
     */
    private void adjustAuthoritiesByTrustTier(CustomUserDetails userDetails, Users user) {
        try {
            // anomaly 체크 (Zero Trust: 차단 우선)
            checkAndHandleAnomalyBlocking(user.getUsername());

            // Redis 에서 trust_score 조회 - username 기반
            Double trustScore = getTrustScore(user.getUsername());
            
            // Trust Tier 결정
            TrustTier tier = determineTrustTier(trustScore);
            
            log.info("User {} trust tier: {} (score: {})", 
                    user.getUsername(), tier, trustScore);
            
            // Tier에 따른 권한 조정
            Set<GrantedAuthority> adjustedAuthorities = adjustAuthorities(
                    userDetails.getAuthorities(), tier, user);
            
            // CustomUserDetails에 조정된 권한 설정
            userDetails.setAdjustedAuthorities(adjustedAuthorities);
            userDetails.setTrustScore(trustScore);
            userDetails.setTrustTier(tier.name());
            
            // 메타데이터 추가
            Map<String, Object> trustMetadata = new HashMap<>();
            trustMetadata.put("trustScore", trustScore);
            trustMetadata.put("trustTier", tier.name());
            trustMetadata.put("adjustmentTime", System.currentTimeMillis());
            userDetails.setTrustMetadata(trustMetadata);
            
            // Redis에 조정된 권한 캐싱
            cacheAdjustedAuthorities(user.getUsername(), adjustedAuthorities, tier);
            
        } catch (Exception e) {
            log.error("Failed to adjust authorities by trust tier for user: {}", user.getUsername(), e);
            // 실패 시 기본 권한 유지
        }
    }
    
    /**
     * Redis에서 threat_score 조회 (username 기반)
     * 프로젝트 센티넬 아키텍처에 따라 threat_score를 사용하고
     * Trust Score = 1.0 - Threat Score로 계산합니다.
     */
    private Double getTrustScore(String username) {
        // ZeroTrustRedisKeys를 통한 중앙 키 관리
        String threatScoreKey = ZeroTrustRedisKeys.threatScore(username);
        
        try {
            Object score = redisTemplate.opsForValue().get(threatScoreKey);
            
            if (score != null) {
                double threatScore;
                if (score instanceof Number) {
                    threatScore = ((Number) score).doubleValue();
                } else if (score instanceof String) {
                    threatScore = Double.parseDouble((String) score);
                } else {
                    threatScore = 0.5; // 기본값
                }
                
                // Trust Score = 1.0 - Threat Score
                double trustScore = 1.0 - threatScore;
                log.debug("Found threat_score {} for username {}, calculated trust_score: {}", 
                        threatScore, username, trustScore);
                return trustScore;
            }
            
            log.debug("No threat score found for username {}, using default trust score: {}", 
                    username, defaultTrustScore);
            
            // threat_score가 없으면 기본 trust score 사용
            // threat_score = 1.0 - defaultTrustScore로 저장
            double defaultThreatScore = 1.0 - defaultTrustScore;
            redisTemplate.opsForValue().set(threatScoreKey, defaultThreatScore, 
                    Duration.ofSeconds(trustScoreCacheTtl));
            
            return defaultTrustScore;
            
        } catch (Exception e) {
            log.error("Failed to get trust score for username {}", username, e);
            return defaultTrustScore;
        }
    }
    
    /**
     * Trust Score를 기반으로 Trust Tier 결정
     */
    private TrustTier determineTrustTier(Double trustScore) {
        if (trustScore >= tier1Threshold) {
            return TrustTier.TIER_1;
        } else if (trustScore >= tier2Threshold) {
            return TrustTier.TIER_2;
        } else if (trustScore >= tier3Threshold) {
            return TrustTier.TIER_3;
        } else {
            return TrustTier.TIER_4;
        }
    }
    
    /**
     * Trust Tier에 따라 권한 조정
     */
    private Set<GrantedAuthority> adjustAuthorities(
            Collection<? extends GrantedAuthority> originalAuthorities,
            TrustTier tier, Users user) {
        
        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>();
        
        switch (tier) {
            case TIER_1:
                // Tier 1: 모든 권한 유지
                adjustedAuthorities.addAll(originalAuthorities);
                break;
                
            case TIER_2:
                // Tier 2: 민감한 작업 권한 제거
                adjustedAuthorities.addAll(originalAuthorities.stream()
                        .filter(auth -> !isSensitiveAuthority(auth))
                        .collect(Collectors.toSet()));
                // 기본 사용자 권한은 유지
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                break;
                
            case TIER_3:
                // Tier 3: 읽기 전용 권한만
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                adjustedAuthorities.add(new SimpleGrantedAuthority("PERMISSION_READ"));
                // 읽기 관련 권한만 유지
                adjustedAuthorities.addAll(originalAuthorities.stream()
                        .filter(auth -> isReadOnlyAuthority(auth))
                        .collect(Collectors.toSet()));
                break;
                
            case TIER_4:
                // Tier 4: 최소 권한만
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_MINIMAL"));
                adjustedAuthorities.add(new SimpleGrantedAuthority("PERMISSION_VIEW_PROFILE"));
                break;
        }
        
        log.debug("Adjusted authorities for user {} (Tier {}): from {} to {} authorities", 
                user.getUsername(), tier, originalAuthorities.size(), adjustedAuthorities.size());
        
        return adjustedAuthorities;
    }
    
    /**
     * 민감한 권한 여부 확인
     */
    private boolean isSensitiveAuthority(GrantedAuthority authority) {
        String authName = authority.getAuthority();
        return authName.contains("ADMIN") || 
               authName.contains("DELETE") || 
               authName.contains("MODIFY_CRITICAL") ||
               authName.contains("EXECUTE") ||
               authName.contains("APPROVAL");
    }
    
    /**
     * 읽기 전용 권한 여부 확인
     */
    private boolean isReadOnlyAuthority(GrantedAuthority authority) {
        String authName = authority.getAuthority();
        return authName.contains("READ") || 
               authName.contains("VIEW") || 
               authName.contains("LIST") ||
               authName.contains("SEARCH");
    }
    
    /**
     * 조정된 권한을 Redis에 캐싱
     */
    private void cacheAdjustedAuthorities(String username, Set<GrantedAuthority> authorities, 
                                          TrustTier tier) {
        try {
            // 프로젝트 센티넬 키 체계에 맞춤
            String cacheKey = "user:authorities:" + username;
            
            Map<String, Object> authCache = new HashMap<>();
            authCache.put("authorities", authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));
            authCache.put("tier", tier.name());
            authCache.put("timestamp", System.currentTimeMillis());
            
            redisTemplate.opsForValue().set(cacheKey, authCache, 
                    Duration.ofSeconds(trustScoreCacheTtl));
            
        } catch (Exception e) {
            log.warn("Failed to cache adjusted authorities for user {}", username, e);
        }
    }
    
    /**
     * Trust Tier 열거형
     */
    public enum TrustTier {
        TIER_1("Full Trust - All Permissions"),
        TIER_2("High Trust - Limited Sensitive Operations"),
        TIER_3("Medium Trust - Read Only"),
        TIER_4("Low Trust - Minimal Access");
        
        private final String description;
        
        TrustTier(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 사용자의 현재 Threat Score 업데이트 (username 기반)
     * SecurityPlaneAgent 에서 호출될 수 있는 public 메서드
     * 
     * 주의: 이 메서드는 직접 호출하지 말고 SecurityPlaneAgent가 관리해야 합니다.
     */
    public void updateThreatScore(String username, double newThreatScore) {
        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(username);
            
            // 점수 범위 검증 (0.0 ~ 1.0)
            double validatedScore = Math.max(0.0, Math.min(1.0, newThreatScore));
            
            redisTemplate.opsForValue().set(threatScoreKey, validatedScore, 
                    Duration.ofSeconds(trustScoreCacheTtl));
            
            // 권한 캐시 무효화 (다음 요청 시 재계산되도록)
            String authCacheKey = "user:authorities:" + username;
            redisTemplate.delete(authCacheKey);
            
            double trustScore = 1.0 - validatedScore;
            log.info("Updated threat score for username {}: {} (trust score: {})", 
                    username, validatedScore, trustScore);
            
        } catch (Exception e) {
            log.error("Failed to update threat score for username {}", username, e);
        }
    }

    /**
     * 이상 탐지 플래그 체크 및 차단 (Zero Trust)
     * HCADFilter에서 Authentication.details에 저장한 이상 탐지 정보를 확인합니다.
     *
     * @param username 사용자명
     * @throws AnomalyDetectedException 이상 탐지 시 발생
     */
    private void checkAndHandleAnomalyBlocking(String username) {
        try {
            // Authentication.details에서 이상 탐지 정보 읽기 (HCADFilter에서 설정됨)
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || authentication.getDetails() == null) {
                log.debug("[AIReactiveUserDetailsService] No authentication or details found for anomaly check");
                return;
            }

            Object details = authentication.getDetails();
            if (!(details instanceof Map)) {
                log.debug("[AIReactiveUserDetailsService] Authentication details is not a Map, skipping anomaly check");
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> detailsMap = (Map<String, Object>) details;
            Object anomalyData = detailsMap.get("HCAD_ANOMALY_INFO");

            if (anomalyData != null) {
                log.error("[AIReactiveUserDetailsService] Anomaly detected for user: {} - BLOCKING AUTHENTICATION (Zero Trust)", username);

                // 1. 감사 로그 기록
                logAnomalyBlockEvent(username, anomalyData);

                // 2. 다채널 알림 발송 (비동기)
                sendAnomalyAlert(username, anomalyData);

                // 3. Zero Trust: 무조건 차단
                throw new AnomalyDetectedException(
                    "비정상적인 접근이 감지되었습니다. 인증이 차단되었습니다. " +
                    "본인이 아닌 경우 즉시 비밀번호를 변경하고 관리자에게 문의하세요. " +
                    "정상 사용자의 경우 10분 후 다시 시도하거나 관리자에게 문의하세요."
                );
            }
        } catch (AnomalyDetectedException e) {
            throw e;
        } catch (Exception e) {
            log.error("[AIReactiveUserDetailsService] Failed to check anomaly flag for user: {}", username, e);
            throw new AnomalyDetectedException("보안 검증 실패. 관리자에게 문의하세요.");
        }
    }

    /**
     * 감사 로그 기록 (AuditLogRepository 사용)
     */
    private void logAnomalyBlockEvent(String username, Object anomalyData) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String anomalyDetails = null;
            try {
                anomalyDetails = objectMapper.writeValueAsString(anomalyData);
            } catch (JsonProcessingException e) {
                anomalyDetails = anomalyData.toString();
            }

            AuditLog auditLog = AuditLog.builder()
                .principalName(username)
                .resourceIdentifier("ANOMALY_BLOCK_AUTH")
                .action("ANOMALY_DETECTION_AUTH")
                .decision("DENY")
                .reason("비정상 행동 탐지로 인한 인증 차단 (Zero Trust)")
                .outcome("BLOCKED")
                .resourceUri("AUTHENTICATION")
                .clientIp("unknown")
                .details(anomalyDetails)
                .build();

            auditLogRepository.save(auditLog);
            log.info("[AUDIT] Anomaly block event logged for user: {} (Authentication)", username);

        } catch (Exception e) {
            log.error("[AIReactiveUserDetailsService] Failed to log anomaly block event", e);
        }
    }

    /**
     * 다채널 이상 탐지 알림 발송 (비동기)
     */
    private void sendAnomalyAlert(String username, Object anomalyData) {
        if (notificationService == null) {
            log.warn("[AIReactiveUserDetailsService] NotificationService not available, skipping alert");
            return;
        }

        Mono.fromRunnable(() -> {
            try {
                SecurityEvent event = SecurityEvent.builder()
                    .eventType(SecurityEvent.EventType.ANOMALY_DETECTED)
                    .severity(SecurityEvent.Severity.HIGH)
                    .userId(username)
                    .sourceIp("unknown")
                    .userAgent("unknown")
                    .blocked(true)
                    .description("보안 이상 탐지로 인한 인증 차단")
                    .targetResource("AUTHENTICATION")
                    .build();

                double anomalyScore = extractAnomalyScore(anomalyData);
                ThreatIndicators indicators = ThreatIndicators.builder()
                    .anomalyDetected(true)
                    .anomalyScore(anomalyScore)
                    .riskScore(anomalyScore)
                    .riskLevel("HIGH")
                    .build();

                notificationService.sendSecurityEventNotification(event, indicators)
                    .subscribe(
                        result -> log.info("[AIReactiveUserDetailsService] Anomaly alert sent for user: {}", username),
                        error -> log.error("[AIReactiveUserDetailsService] Failed to send anomaly alert", error)
                    );

            } catch (Exception e) {
                log.error("[AIReactiveUserDetailsService] Error sending anomaly alert", e);
            }
        })
        .subscribeOn(Schedulers.boundedElastic())
        .subscribe();
    }

    /**
     * anomalyData에서 anomalyScore 추출
     */
    private double extractAnomalyScore(Object anomalyData) {
        if (anomalyData instanceof Map) {
            Map<String, Object> data = (Map<String, Object>) anomalyData;
            Object score = data.get("scoreDelta");
            if (score instanceof Number) {
                return ((Number) score).doubleValue() * 100.0;
            }
        }
        return 80.0;
    }
}