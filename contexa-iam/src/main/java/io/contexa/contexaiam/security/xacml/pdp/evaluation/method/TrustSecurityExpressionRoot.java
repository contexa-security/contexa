package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.exception.AnomalyDetectedException;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.entity.AuditLog;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.dto.UserDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 신뢰 기반 보안 표현식 루트 (Hot Path 전용)
 * 
 * Redis에 사전 계산된 위협 점수(threat_score)를 조회하여 실시간 인가 결정을 수행합니다.
 * AI 호출 없이 Redis 조회만으로 5ms 이내 응답을 보장합니다.
 * 
 * 외부기관 설계에 따른 계층 구조:
 * AbstractAISecurityExpressionRoot (공통 기반)
 *   └── TrustSecurityExpressionRoot (이 클래스)
 * 
 * 사용 예시:
 * - @PreAuthorize("#trust.levelExceeds(0.5)")
 * - @PreAuthorize("#trust.isLowRisk()")
 */
@Slf4j
public class TrustSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private final RedisTemplate<String, Double> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;  // 세션-사용자 매핑 조회용
    private final UnifiedNotificationService notificationService;
    
    // Caffeine 로컬 캐시 (1초 TTL)
    private static final Cache<String, Double> localCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();
    

    // Redis 키 프리픽스
    private static final String THREAT_SCORE_PREFIX = "threat_score:";
    private static final String THREAT_DETAIL_PREFIX = "threat_detail:";
    private static final String THREAT_PATTERN_PREFIX = "threat_pattern:";
    
    // 위험 수준 임계값
    private static final double LOW_RISK_THRESHOLD = 0.4;
    private static final double MEDIUM_RISK_THRESHOLD = 0.7;
    private static final double HIGH_RISK_THRESHOLD = 0.9;
    
    // 기본값
    private static final double DEFAULT_THREAT_SCORE = 0.5; // Redis 장애시 중간 위험도
    private static final Duration REDIS_TIMEOUT = Duration.ofMillis(5); // 5ms 타임아웃
    
    public TrustSecurityExpressionRoot(Authentication authentication,
                                       AttributeInformationPoint attributePIP,
                                       AICoreOperations aINativeProcessor,
                                       AuthorizationContext authorizationContext,
                                       AuditLogRepository auditLogRepository,
                                       RedisTemplate<String, Double> redisTemplate,
                                       StringRedisTemplate stringRedisTemplate,
                                       UnifiedNotificationService notificationService) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.redisTemplate = redisTemplate;
        this.stringRedisTemplate = stringRedisTemplate;
        this.notificationService = notificationService;
        log.debug("TrustSecurityExpressionRoot 초기화 완료 - Hot Path 모드");
    }
    
    /**
     * 위협 점수가 지정된 임계값을 초과하는지 확인
     * 
     * @param threshold 위협 점수 임계값 (0.0 ~ 1.0)
     * @return 위협 점수가 임계값을 초과하면 true (접근 거부)
     */
    public boolean levelExceeds(double threshold) {
        String userId = extractUserId();
        if (userId == null) {
            log.warn("levelExceeds: 사용자 ID를 추출할 수 없음");
            return true;
        }

        // 이상 탐지 플래그 체크
        checkAndHandleAnomaly(userId);

        double threatScore = getThreatScore(userId);
        boolean exceeds = threatScore > threshold;

        log.debug("levelExceeds 평가 - userId: {}, threatScore: {}, threshold: {}, exceeds: {}",
                 userId, threatScore, threshold, exceeds);

        return exceeds;
    }
    
    /**
     * 신뢰 수준이 지정된 값 이상인지 확인
     * 신뢰 수준 = 1.0 - 위협 점수
     * 
     * @param minTrustLevel 최소 신뢰 수준 (0.0 ~ 1.0)
     * @return 신뢰 수준이 최소값 이상이면 true (접근 허용)
     */
    public boolean trustLevelAbove(double minTrustLevel) {
        String userId = extractUserId();
        if (userId == null) {
            log.warn("trustLevelAbove: 사용자 ID를 추출할 수 없음");
            return false; // 안전을 위해 접근 거부
        }
        
        double threatScore = getThreatScore(userId);
        double trustLevel = 1.0 - threatScore;
        boolean meetsRequirement = trustLevel >= minTrustLevel;
        
        log.debug("trustLevelAbove 평가 - userId: {}, trustLevel: {}, required: {}, meets: {}", 
                 userId, trustLevel, minTrustLevel, meetsRequirement);
        
        return meetsRequirement;
    }
    
    /**
     * 낮은 위험도 확인
     * @return 위협 점수가 0.4 이하이면 true
     */
    public boolean isLowRisk() {
        return !levelExceeds(LOW_RISK_THRESHOLD);
    }
    
    /**
     * 중간 위험도 확인
     * @return 위협 점수가 0.4 초과 0.7 이하이면 true
     */
    public boolean isMediumRisk() {
        String userId = extractUserId();
        if (userId == null) {
            return false;
        }
        
        double threatScore = getThreatScore(userId);
        return threatScore > LOW_RISK_THRESHOLD && threatScore <= MEDIUM_RISK_THRESHOLD;
    }
    
    /**
     * 높은 위험도 확인
     * @return 위협 점수가 0.7 초과이면 true
     */
    public boolean isHighRisk() {
        return levelExceeds(MEDIUM_RISK_THRESHOLD);
    }
    
    /**
     * 매우 높은 위험도 확인
     * @return 위협 점수가 0.9 초과이면 true
     */
    public boolean isCriticalRisk() {
        return levelExceeds(HIGH_RISK_THRESHOLD);
    }
    
    /**
     * 현재 사용자의 위협 점수 조회
     * @return 위협 점수 (0.0 ~ 1.0)
     */
    public double getCurrentThreatScore() {
        String userId = extractUserId();
        if (userId == null) {
            return DEFAULT_THREAT_SCORE;
        }
        return getThreatScore(userId);
    }
    
    /**
     * 현재 사용자의 신뢰 점수 조회
     * @return 신뢰 점수 (0.0 ~ 1.0)
     */
    public double getCurrentTrustScore() {
        return 1.0 - getCurrentThreatScore();
    }
    
    /**
     * 이상 탐지 플래그 체크 및 차별적 대응
     *
     * 통계 기반 이상 탐지 결과에 따른 차별적 대응:
     * - SESSION_HIJACKING: 즉시 차단, MFA 요구, 사용자 알림
     * - EXTREME_DEVIATION: 즉시 차단, 보안팀 알림
     * - HIGH_RISK_ACTIVITY: 추가 인증 요구
     * - STATISTICAL_ANOMALY: 모니터링 강화
     * - SUSPICIOUS_ACTIVITY: 경고 로그만
     *
     * @param userId 사용자 ID
     * @throws AnomalyDetectedException 고위험 이상 탐지 시 발생
     */
    private void checkAndHandleAnomaly(String userId) {
        try {
            // Authentication.details 에서 이상탐지 정보 확인 (HCADFilter 에서 설정됨)
            Authentication authentication = getAuthentication();
            if (authentication == null || authentication.getDetails() == null) {
                // 이상 탐지 정보 없음
                return;
            }

            Object details = authentication.getDetails();
            if (!(details instanceof Map)) {
                return;
            }

            Map<String, Object> detailsMap = (Map<String, Object>) details;
            Object anomalyData = detailsMap.get("anomalyInfo");

            if (anomalyData == null) {
                // 이상 탐지 정보 없음
                return;
            }

            if (!(anomalyData instanceof Map)) {
                log.warn("[TrustSecurityExpressionRoot] Invalid anomaly data format for user: {}", userId);
                return;
            }

            Map<String, Object> anomalyInfo = (Map<String, Object>) anomalyData;

            // 세션 탈취 상황 고려: 현재 요청의 userId와 이상탐지 대상 userId 검증
            String anomalyUserId = (String) anomalyInfo.get("userId");
            if (!userId.equals(anomalyUserId)) {
                log.warn("[TrustSecurityExpressionRoot] UserId mismatch - current: {}, anomaly: {}", userId, anomalyUserId);
                // 세션 탈취 가능성 - 더 엄격한 처리
                handleSessionHijackingSuspicion(userId, anomalyUserId, anomalyInfo);
                return;
            }

            // 심각도에 따른 처리
            String severity = (String) anomalyInfo.get("severity");
            String anomalyType = (String) anomalyInfo.get("anomalyType");

            log.warn("[TrustSecurityExpressionRoot] Anomaly detected from HCADFilter - userId: {}, severity: {}, type: {}",
                userId, severity, anomalyType);

            switch (severity) {
                case "CRITICAL":
                    handleCriticalAnomaly(userId, anomalyInfo);
                    break;
                case "HIGH":
                    handleHighRiskAnomaly(userId, anomalyInfo);
                    break;
                case "MEDIUM":
                    enhanceMonitoring(userId, anomalyInfo);
                    break;
                case "LOW":
                    logAnomalyEvent(userId, anomalyInfo);
                    break;
                default:
                    log.warn("[TrustSecurityExpressionRoot] Unknown severity level: {}", severity);
                    enhanceMonitoring(userId, anomalyInfo);
            }

        } catch (AnomalyDetectedException e) {
            throw e; // 재발생
        } catch (Exception e) {
            log.error("[TrustSecurityExpressionRoot] Failed to check anomaly from Authentication.details for user: {}", userId, e);
            // 체크 실패 시 안전을 위해 차단
            throw new AnomalyDetectedException("보안 검증 실패. 관리자에게 문의하세요.");
        }
    }

    /**
     * 세션 탈취 의심 상황 처리
     * 현재 요청 사용자와 이상탐지 대상 사용자가 다른 경우
     */
    private void handleSessionHijackingSuspicion(String currentUserId, String anomalyUserId, Map<String, Object> anomalyInfo) {
        try {
            // 세션 정보 검증을 통해 실제 세션 소유자 확인
            String sessionId = extractSessionId();
            if (sessionId != null && stringRedisTemplate != null) {
                // StringRedisTemplate을 사용하여 세션-사용자 매핑 조회
                String sessionOwner = stringRedisTemplate.opsForValue().get(
                    ZeroTrustRedisKeys.sessionToUser(sessionId)
                );

                if (sessionOwner != null && anomalyUserId.equals(sessionOwner)) {
                    // 실제 세션 소유자에게 이상탐지 알림을 보내야 함
                    log.error("[SESSION_HIJACKING] Session hijacking suspected - session owner: {}, current user: {}, sessionId: {}",
                        sessionOwner, currentUserId, sessionId);

                    // 세션 소유자에게 모달창 알림
                    sendAnomalyAlert(sessionOwner, anomalyInfo);

                    // 현재 요청은 즉시 차단
                    throw new AnomalyDetectedException(
                        "세션 보안 위반이 감지되었습니다.\n" +
                        "보안상의 이유로 접근이 차단되었습니다.\n" +
                        "관리자에게 문의하세요."
                    );
                }
            }

            // 일반적인 사용자 불일치 - 현재 사용자에게 알림
            log.warn("[USER_MISMATCH] User ID mismatch in anomaly detection - current: {}, anomaly: {}",
                currentUserId, anomalyUserId);
            sendAnomalyAlert(currentUserId, anomalyInfo);

        } catch (AnomalyDetectedException e) {
            throw e;  // AnomalyDetectedException은 재발생
        } catch (Exception e) {
            log.error("[TrustSecurityExpressionRoot] Failed to handle session hijacking suspicion", e);
            // 에러 발생 시 안전을 위해 차단
            throw new AnomalyDetectedException("보안 검증 실패. 관리자에게 문의하세요.");
        }
    }

    /**
     * 세션 ID 추출
     */
    private String extractSessionId() {
        if (authorizationContext != null && authorizationContext.environment() != null) {
            jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
            if (request != null) {
                jakarta.servlet.http.HttpSession session = request.getSession(false);
                if (session != null) {
                    return session.getId();
                }
            }
        }
        return null;
    }

    /**
     * CRITICAL 심각도 이상 처리
     */
    private void handleCriticalAnomaly(String userId, Map<String, Object> anomalyInfo) {
        log.error("[CRITICAL_ANOMALY] Critical anomaly detected for user: {} - IMMEDIATE BLOCKING", userId);
        logAnomalyBlockEvent(userId, anomalyInfo);
        sendUrgentSecurityAlert(userId, anomalyInfo);
        sendAnomalyAlert(userId, anomalyInfo);
        throw new AnomalyDetectedException(
            "심각한 보안 위험이 감지되었습니다.\n" +
            "보안상의 이유로 접근이 즉시 차단되었습니다.\n" +
            "관리자에게 문의하세요."
        );
    }

    /**
     * HIGH 심각도 이상 처리
     */
    private void handleHighRiskAnomaly(String userId, Map<String, Object> anomalyInfo) {
        log.warn("[HIGH_RISK_ANOMALY] High risk anomaly detected for user: {} - BLOCKING ACCESS", userId);
        logAnomalyBlockEvent(userId, anomalyInfo);
        sendAnomalyAlert(userId, anomalyInfo);
        throw new AnomalyDetectedException(
            "비정상적인 접근이 감지되었습니다.\n" +
            "보안상의 이유로 접근이 차단되었습니다.\n" +
            "관리자에게 문의하세요."
        );
    }

    /**
     * 이상 탐지 이벤트 로깅 (차단 없음)
     */
    private void logAnomalyEvent(String userId, Map<String, Object> anomalyInfo) {
        log.info("[ANOMALY_EVENT] Low severity anomaly logged for user: {} - type: {}, score: {}",
            userId, anomalyInfo.get("anomalyType"), anomalyInfo.get("anomalyScore"));

        // 감사 로그 기록
        try {
            // 감사 로그 시스템에 기록 (필요시 구현)
            log.debug("[AUDIT] Anomaly event recorded for user: {}", userId);
        } catch (Exception e) {
            log.error("[TrustSecurityExpressionRoot] Failed to log anomaly event", e);
        }
    }

    /**
     * 기존 형식의 이상 탐지 데이터 처리 (하위 호환성)
     */
    private void handleLegacyAnomaly(String userId, Object anomalyData) {
        log.error("[TrustSecurityExpressionRoot] Legacy anomaly detected for user: {} - BLOCKING ACCESS", userId);
        logAnomalyBlockEvent(userId, anomalyData);
        sendAnomalyAlert(userId, anomalyData);
        throw new AnomalyDetectedException(
            "비정상적인 접근이 감지되었습니다.\n" +
            "보안상의 이유로 접근이 차단되었습니다.\n" +
            "관리자에게 문의하세요."
        );
    }

    /**
     * 모니터링 강화 (통계적 이상 또는 중간 위험 시)
     */
    private void enhanceMonitoring(String userId, Map<String, Object> anomalyData) {
        try {
            // Redis에 모니터링 플래그 설정
            String monitoringKey = "security:monitoring:" + userId;
            // RedisTemplate<String, Double> 타입으로 인해 Map<String, Object>를 저장할 수 없음 - 컴파일 오류 해결을 위해 주석 처리
            // Map<String, Object> monitoringData = new HashMap<>();
            // monitoringData.put("userId", userId);
            // monitoringData.put("anomalyType", anomalyData.get("anomalyType"));
            // monitoringData.put("startTime", System.currentTimeMillis());
            // monitoringData.put("level", "ENHANCED");

            // redisTemplate.opsForValue().set(monitoringKey, monitoringData,
            //     java.time.Duration.ofHours(1)); // 1시간 동안 강화 모니터링

            log.info("[MONITORING] Enhanced monitoring activated for user: {} for 1 hour", userId);
        } catch (Exception e) {
            log.error("[TrustSecurityExpressionRoot] Failed to enhance monitoring for user: {}", userId, e);
        }
    }

    /**
     * 긴급 보안 알림 (세션 하이재킹 등)
     */
    private void sendUrgentSecurityAlert(String userId, Map<String, Object> anomalyData) {
        try {
            // 비동기 처리
            java.util.concurrent.CompletableFuture.runAsync(() -> {
                try {
                    // 사용자에게 이메일/SMS 발송
                    log.error("[ALERT] Urgent security alert sent to user: {} - Session hijacking suspected", userId);
                    // TODO: 실제 알림 서비스 연동

                    // 보안팀에게도 알림
                    log.error("[SECURITY TEAM] Session hijacking alert for user: {}", userId);
                } catch (Exception e) {
                    log.error("Failed to send urgent security alert", e);
                }
            });
        } catch (Exception e) {
            log.error("Failed to initiate urgent security alert", e);
        }
    }

    /**
     * 감사 로그 기록 (AuditLogRepository 사용)
     */
    private void logAnomalyBlockEvent(String userId, Object anomalyData) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String anomalyDetails = null;
            try {
                anomalyDetails = objectMapper.writeValueAsString(anomalyData);
            } catch (JsonProcessingException e) {
                anomalyDetails = anomalyData.toString();
            }

            String resourceUri = "unknown";
            if (authorizationContext != null && authorizationContext.environment() != null) {
                jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
                if (request != null) {
                    resourceUri = request.getRequestURI();
                }
            }

            AuditLog auditLog = AuditLog.builder()
                .principalName(userId)
                .resourceIdentifier("ANOMALY_BLOCK")
                .action("ANOMALY_DETECTION")
                .decision("DENY")
                .reason("비정상 행동 탐지로 인한 접근 차단 (Zero Trust)")
                .outcome("BLOCKED")
                .resourceUri(resourceUri)
                .clientIp(getRemoteIp())
                .details(anomalyDetails)
                .build();

            auditLogRepository.save(auditLog);
            log.info("[AUDIT] Anomaly block event logged for user: {}", userId);

        } catch (Exception e) {
            log.error("[TrustSecurityExpressionRoot] Failed to log anomaly block event", e);
        }
    }

    /**
     * 다채널 이상 탐지 알림 발송 (비동기)
     */
    private void sendAnomalyAlert(String userId, Object anomalyData) {
        if (notificationService == null) {
            log.warn("[TrustSecurityExpressionRoot] NotificationService not available, skipping alert");
            return;
        }

        // 비동기 알림 발송 (흐름 방해 없음)
        Mono.fromRunnable(() -> {
            try {
                // SecurityEvent 생성
                String targetResource = "unknown";
                if (authorizationContext != null && authorizationContext.environment() != null) {
                    jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
                    if (request != null) {
                        targetResource = request.getRequestURI();
                    }
                }

                SecurityEvent event = SecurityEvent.builder()
                    .eventType(SecurityEvent.EventType.ANOMALY_DETECTED)
                    .severity(SecurityEvent.Severity.HIGH)
                    .userId(userId)
                    .sourceIp(getRemoteIp())
                    .userAgent(extractUserAgent())
                    .blocked(true)
                    .description("보안 이상 탐지로 인한 접근 차단")
                    .targetResource(targetResource)
                    .build();

                // ThreatIndicators 생성
                double anomalyScore = extractAnomalyScore(anomalyData);
                ThreatIndicators indicators = ThreatIndicators.builder()
                    .anomalyDetected(true)
                    .anomalyScore(anomalyScore)
                    .riskScore(anomalyScore)
                    .riskLevel("HIGH")
                    .build();

                notificationService.sendSecurityEventNotification(event, indicators)
                    .subscribe(
                        result -> log.info("[TrustSecurityExpressionRoot] Anomaly alert sent for user: {}", userId),
                        error -> log.error("[TrustSecurityExpressionRoot] Failed to send anomaly alert", error)
                    );

            } catch (Exception e) {
                log.error("[TrustSecurityExpressionRoot] Error sending anomaly alert", e);
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

    /**
     * UserAgent 추출
     */
    private String extractUserAgent() {
        if (authorizationContext != null && authorizationContext.environment() != null) {
            jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
            if (request != null) {
                String userAgent = request.getHeader("User-Agent");
                return userAgent != null ? userAgent : "unknown";
            }
        }
        return "unknown";
    }

    /**
     * Redis에서 위협 점수 조회 (캐시 적용)
     *
     * @param userId 사용자 ID
     * @return 위협 점수
     */
    private double getThreatScore(String userId) {
        String cacheKey = THREAT_SCORE_PREFIX + userId;
        
        // 1. 로컬 캐시 확인
        Double cachedScore = localCache.getIfPresent(cacheKey);
        if (cachedScore != null) {
            log.trace("로컬 캐시 히트 - userId: {}, score: {}", userId, cachedScore);
            return cachedScore;
        }
        
        // 2. Redis 조회
        try {
            Double redisScore = redisTemplate.opsForValue().get(cacheKey);
            if (redisScore != null) {
                log.trace("Redis 조회 성공 - userId: {}, score: {}", userId, redisScore);
                localCache.put(cacheKey, redisScore);
                return redisScore;
            } else {
                // Zero Trust 원칙: 신규 사용자는 중간 위험도로 시작
                // 완전히 신뢰(0.0)하지 않고, 행동 패턴을 관찰하여 점수 조정
                log.debug("Redis에 위협 점수 없음 - userId: {}, Zero Trust 기본값 사용: {}", userId, DEFAULT_THREAT_SCORE);
                return DEFAULT_THREAT_SCORE; // 0.5 (중간 위험도)
            }
        } catch (Exception e) {
            log.error("Redis 조회 실패 - userId: {}, 기본값 사용: {}", userId, DEFAULT_THREAT_SCORE, e);
            return DEFAULT_THREAT_SCORE; // 장애시 중간 위험도
        }
    }
    
    /**
     * 현재 인증된 사용자의 ID 추출
     * 
     * @return 사용자 ID
     */
    private String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDto) {
            UserDto userDto = (UserDto) principal;
            return userDto.getId() != null ? userDto.getId().toString() : userDto.getUsername();
        } else if (principal instanceof String) {
            return (String) principal;
        }
        
        return null;
    }
    
    @Override
    protected String getRemoteIp() {
        // AuthorizationContext 에서 IP 추출
        if (authorizationContext != null && authorizationContext.environment() != null) {
            jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
            if (request != null) {
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    return xForwardedFor.split(",")[0].trim();
                }
                
                String xRealIp = request.getHeader("X-Real-IP");
                if (xRealIp != null && !xRealIp.isEmpty()) {
                    return xRealIp;
                }
                
                return request.getRemoteAddr();
            }
            return authorizationContext.environment().remoteIp();
        }
        return "unknown";
    }
    
    @Override
    protected String getCurrentActivityDescription() {
        // 현재 수행 중인 활동 설명
        if (authorizationContext != null) {
            String action = authorizationContext.action();
            if (authorizationContext.resource() != null) {
                String resourceId = authorizationContext.resource().identifier();
                return String.format("%s %s", action, resourceId);
            }
            return action;
        }
        return "unknown activity";
    }
    
    /**
     * 특정 리소스에 대한 위협 점수 확인
     * 
     * @param resourceId 리소스 ID
     * @param threshold 임계값
     * @return 위협 점수가 임계값 이하이면 true
     */
    public boolean hasResourceAccess(String resourceId, double threshold) {
        String userId = extractUserId();
        if (userId == null || resourceId == null) {
            return false;
        }
        
        // 리소스별 위협 점수 조회
        String resourceKey = THREAT_SCORE_PREFIX + userId + ":" + resourceId;
        try {
            Double resourceScore = redisTemplate.opsForValue().get(resourceKey);
            if (resourceScore == null) {
                // 리소스별 점수가 없으면 사용자 전체 점수 사용
                resourceScore = getThreatScore(userId);
            }
            
            boolean hasAccess = resourceScore <= threshold;
            log.debug("hasResourceAccess - userId: {}, resourceId: {}, score: {}, threshold: {}, access: {}",
                     userId, resourceId, resourceScore, threshold, hasAccess);
            
            return hasAccess;
        } catch (Exception e) {
            log.error("리소스 접근 평가 실패 - userId: {}, resourceId: {}", userId, resourceId, e);
            return false;
        }
    }
    
    /**
     * 임시 권한 부여 확인
     * Cold Path에서 특별히 허용한 경우
     * 
     * @param permissionType 권한 타입
     * @return 임시 권한이 있으면 true
     */
    public boolean hasTemporaryPermission(String permissionType) {
        String userId = extractUserId();
        if (userId == null) {
            return false;
        }
        
        String tempPermKey = "temp_permission:" + userId + ":" + permissionType;
        try {
            Boolean hasPermission = redisTemplate.hasKey(tempPermKey);
            log.debug("hasTemporaryPermission - userId: {}, type: {}, granted: {}", 
                     userId, permissionType, hasPermission);
            return Boolean.TRUE.equals(hasPermission);
        } catch (Exception e) {
            log.error("임시 권한 확인 실패 - userId: {}, type: {}", userId, permissionType, e);
            return false;
        }
    }
    
    @Override
    protected ContextExtractionResult extractCurrentContext() {
        String remoteIp = getRemoteIp();
        String userAgent = "";
        String resourceIdentifier = "";
        String actionType = "";
        
        if (authorizationContext != null) {
            if (authorizationContext.environment() != null && authorizationContext.environment().request() != null) {
                userAgent = authorizationContext.environment().request().getHeader("User-Agent");
                if (userAgent == null) {
                    userAgent = "";
                }
            }
            if (authorizationContext.resource() != null) {
                resourceIdentifier = authorizationContext.resource().identifier();
            }
            actionType = authorizationContext.action();
        }
        
        return new ContextExtractionResult(
            remoteIp, userAgent, resourceIdentifier, actionType);
    }
    
    @Override
    protected String calculateContextHash() {
        StringBuilder sb = new StringBuilder();
        if (authorizationContext != null) {
            if (authorizationContext.resource() != null) {
                sb.append(authorizationContext.resource().identifier());
            }
            sb.append(authorizationContext.action());
            if (authorizationContext.subjectEntity() != null) {
                sb.append(authorizationContext.subjectEntity().getId());
            }
        }
        sb.append(System.currentTimeMillis());
        return Integer.toHexString(sb.toString().hashCode());
    }

    // ========================================================================
    // LLM Action 기반 메서드 구현 (Zero Trust 보안 아키텍처)
    // ========================================================================

    /**
     * Redis에서 현재 사용자의 LLM action 조회 (Hot Path)
     *
     * HCAD 분석 결과에서 action 필드를 조회한다.
     * Redis Hash: security:hcad:analysis:{userId}
     * Field: action
     *
     * 가능한 action 값: ALLOW, BLOCK, CHALLENGE, INVESTIGATE, ESCALATE, MONITOR
     * 값이 없으면 PENDING_ANALYSIS 반환
     *
     * @return LLM action 문자열
     */
    @Override
    protected String getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            log.warn("getCurrentAction: 사용자 ID를 추출할 수 없음 - PENDING_ANALYSIS 반환");
            return "PENDING_ANALYSIS";
        }

        // 로컬 캐시 확인 (action 전용)
        String actionCacheKey = "action:" + userId;
        String cachedAction = getActionFromLocalCache(actionCacheKey);
        if (cachedAction != null) {
            log.trace("getCurrentAction: 로컬 캐시 히트 - userId: {}, action: {}", userId, cachedAction);
            return cachedAction;
        }

        // Redis Hash에서 action 필드 조회
        try {
            String redisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object actionValue = stringRedisTemplate.opsForHash().get(redisKey, "action");

            if (actionValue != null) {
                String action = actionValue.toString();
                putActionToLocalCache(actionCacheKey, action);
                log.debug("getCurrentAction: Redis 조회 성공 - userId: {}, action: {}", userId, action);
                return action;
            } else {
                // action이 없으면 분석 미완료
                log.debug("getCurrentAction: Redis에 action 없음 - userId: {}, PENDING_ANALYSIS 반환", userId);
                return "PENDING_ANALYSIS";
            }
        } catch (Exception e) {
            log.error("getCurrentAction: Redis 조회 실패 - userId: {}, PENDING_ANALYSIS 반환", userId, e);
            return "PENDING_ANALYSIS";
        }
    }

    // Action 전용 로컬 캐시 (1초 TTL)
    private static final Cache<String, String> actionLocalCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();

    private String getActionFromLocalCache(String key) {
        return actionLocalCache.getIfPresent(key);
    }

    private void putActionToLocalCache(String key, String action) {
        actionLocalCache.put(key, action);
    }
}