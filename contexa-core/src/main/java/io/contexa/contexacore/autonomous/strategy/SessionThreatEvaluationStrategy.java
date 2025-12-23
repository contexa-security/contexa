package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SessionThreatIndicators;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 세션 위협 평가 전략
 * 
 * 세션 하이재킹, 세션 고정 공격, 세션 리플레이 등
 * 세션 관련 위협을 탐지하고 평가합니다.
 * 
 * 주요 검사 항목:
 * - IP 주소 변경 감지
 * - User-Agent 변경 감지
 * - 비정상적인 시간 패턴
 * - 지리적 위치 이상
 * - 세션 활동 패턴 분석
 */
@Slf4j
@RequiredArgsConstructor
public class SessionThreatEvaluationStrategy implements ThreatEvaluationStrategy {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${security.session.threat.ip-change-risk:0.4}")
    private double ipChangeRisk;
    
    @Value("${security.session.threat.ua-change-risk:0.3}")
    private double userAgentChangeRisk;
    
    @Value("${security.session.threat.rapid-access-threshold-ms:100}")
    private long rapidAccessThresholdMs;
    
    @Value("${security.session.threat.rapid-access-risk:0.2}")
    private double rapidAccessRisk;
    
    @Value("${security.session.hijack.channel:security:session:hijack:event}")
    private String sessionHijackChannel;
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.debug("Evaluating session threat for event: {}", event.getEventId());
        
        // 세션 ID가 없으면 평가 불가
        if (event.getSessionId() == null) {
            return createMinimalAssessment(event);
        }
        
        // 세션 컨텍스트 분석
        SessionThreatIndicators indicators = analyzeSessionContext(event);

        // 위협 지표 변환
        List<ThreatIndicator> threatIndicatorObjects = convertToThreatIndicators(indicators);

        // String 리스트로 변환 (ThreatAssessment에 맞게)
        List<String> threatIndicatorStrings = indicators.getIndicators().entrySet().stream()
            .map(e -> e.getKey() + ": " + e.getValue())
            .collect(Collectors.toList());

        // 권장 액션 생성
        List<String> recommendedActions = generateRecommendedActions(indicators);

        // AI Native: action 직접 결정 (threatLevel 기반 규칙 제거)
        String action = determineAction(indicators);

        // 높은 위험도의 경우 세션 무효화 이벤트 발행
        if (indicators.shouldInvalidateSession()) {
            publishSessionInvalidationEvent(event, indicators);
        }

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .riskScore(indicators.getAdditionalRisk())
            .indicators(threatIndicatorStrings)
            .recommendedActions(recommendedActions)
            .confidence(calculateConfidenceScore(event))
            .metadata(createMetadata(indicators))
            .action(action)  // AI Native: action 직접 설정
            .build();
    }
    
    /**
     * 세션 컨텍스트 분석 (userId 기반으로 개선)
     */
    private SessionThreatIndicators analyzeSessionContext(SecurityEvent event) {
        SessionThreatIndicators indicators = new SessionThreatIndicators();
        
        try {
            // Zero Trust: userId 기반 컨텍스트 우선 조회
            Map<Object, Object> previousContext = null;
            
            if (event.hasUserId()) {
                // 사용자 컨텍스트에서 세션 정보 조회 (권장)
                String userContextKey = ZeroTrustRedisKeys.userContext(event.getUserId());
                try {
                    UserSecurityContext userContext = (UserSecurityContext) redisTemplate.opsForValue().get(userContextKey);

                    if (userContext != null && event.getSessionId() != null) {
                        // 사용자 컨텍스트에서 해당 세션 찾기
                        previousContext = extractSessionContext(userContext, event.getSessionId());
                    }
                } catch (org.springframework.dao.InvalidDataAccessApiUsageException e) {
                    // WRONGTYPE 에러: 키가 다른 타입으로 저장되어 있음 (레거시 데이터)
                    log.warn("Redis key type mismatch for userContext: {} - deleting legacy data", userContextKey);
                    redisTemplate.delete(userContextKey);
                }
            }

            // AI Native: legacySessionContext 제거 (v3.1.0)
            // - 레거시 세션 기반 조회 완전 제거
            // - userId 기반 컨텍스트만 사용

            if (previousContext != null && !previousContext.isEmpty()) {
                // IP 변경 검사
                checkIpChange(event, previousContext, indicators);
                
                // User-Agent 변경 검사
                checkUserAgentChange(event, previousContext, indicators);
                
                // 시간 패턴 검사
                checkTimePattern(event, previousContext, indicators);
                
                // 지리적 위치 검사 (향후 구현)
                checkGeographicAnomaly(event, previousContext, indicators);
            }
            
            // 현재 컨텍스트 저장
            saveCurrentContext(event);
            
        } catch (Exception e) {
            log.error("Failed to analyze session context", e);
            indicators.addIndicator("ERROR", "Context analysis failed: " + e.getMessage());
        }
        
        return indicators;
    }
    
    /**
     * IP 변경 검사
     */
    private void checkIpChange(SecurityEvent event, Map<Object, Object> previousContext, 
                               SessionThreatIndicators indicators) {
        String previousIp = (String) previousContext.get("sourceIp");
        if (previousIp != null && !previousIp.equals(event.getSourceIp())) {
            indicators.setIpChanged(true);
            indicators.addRisk(ipChangeRisk);
            indicators.addIndicator("IP_CHANGED", 
                String.format("%s -> %s", previousIp, event.getSourceIp()));
            
            log.warn("IP change detected for session {}: {} -> {}", 
                event.getSessionId(), previousIp, event.getSourceIp());
        }
    }
    
    /**
     * User-Agent 변경 검사
     */
    private void checkUserAgentChange(SecurityEvent event, Map<Object, Object> previousContext,
                                     SessionThreatIndicators indicators) {
        String previousUA = (String) previousContext.get("userAgent");
        if (previousUA != null && !previousUA.equals(event.getUserAgent())) {
            indicators.setUserAgentChanged(true);
            indicators.addRisk(userAgentChangeRisk);
            indicators.addIndicator("UA_CHANGED", "User-Agent changed");
            
            log.warn("User-Agent change detected for session {}", event.getSessionId());
        }
    }
    
    /**
     * 시간 패턴 검사
     */
    private void checkTimePattern(SecurityEvent event, Map<Object, Object> previousContext,
                                 SessionThreatIndicators indicators) {
        Long lastAccess = (Long) previousContext.get("lastAccess");
        if (lastAccess != null) {
            long timeDiff = System.currentTimeMillis() - lastAccess;
            
            if (timeDiff < rapidAccessThresholdMs) {
                indicators.setSuspiciousActivity(true);
                indicators.addRisk(rapidAccessRisk);
                indicators.addIndicator("RAPID_ACCESS", 
                    String.format("Too fast: %dms", timeDiff));
                
                log.warn("Rapid access detected for session {}: {}ms", 
                    event.getSessionId(), timeDiff);
            }
        }
    }
    
    /**
     * 지리적 이상 검사
     * 
     * IP 주소 기반으로 지리적 위치를 분석하고 이상 패턴을 탐지합니다.
     * 내부 IP 데이터베이스와 패턴 분석을 활용합니다.
     */
    private void checkGeographicAnomaly(SecurityEvent event, Map<Object, Object> previousContext,
                                       SessionThreatIndicators indicators) {
        
        String currentIp = event.getSourceIp();
        String previousIp = (String) previousContext.get("sourceIp");
        
        if (currentIp == null || previousIp == null) {
            return;
        }
        
        try {
            // 1. IP 지리적 위치 추정 (간단한 로직 사용)
            GeoLocation currentLocation = estimateGeoLocation(currentIp);
            GeoLocation previousLocation = estimateGeoLocation(previousIp);
            
            if (currentLocation == null || previousLocation == null) {
                return;
            }
            
            // 2. 물리적 거리 계산
            double distance = calculateDistance(previousLocation, currentLocation);

            // 3. 시간 차이 계산
            LocalDateTime previousTime = (LocalDateTime) previousContext.get("timestamp");
            LocalDateTime currentTime = event.getTimestamp();

            if (previousTime == null || currentTime == null) {
                return;
            }

            long timeDiffMinutes = Duration.between(previousTime, currentTime).toMinutes();
            
            // 4. 물리적으로 불가능한 이동 검사 (1분당 최대 20km 이동 가능으로 가정 - 비행기 속도)
            double maxPossibleDistance = timeDiffMinutes * 20.0; // km
            
            if (distance > maxPossibleDistance) {
                indicators.addIndicator("IMPOSSIBLE_TRAVEL", 0.95, 
                    String.format("Impossible travel detected: %.2f km in %d minutes", 
                        distance, timeDiffMinutes));
                indicators.incrementScore(0.8);
                log.warn("Impossible travel detected for user {}: {} -> {} ({} km in {} min)",
                    event.getUserId(), previousIp, currentIp, distance, timeDiffMinutes);
            }
            
            // 5. 국가 변경 검사
            if (!currentLocation.country.equals(previousLocation.country)) {
                indicators.addIndicator("COUNTRY_CHANGE", 0.7,
                    "Country changed from " + previousLocation.country + " to " + currentLocation.country);
                indicators.incrementScore(0.3);
            }
            
            // 6. 대륙 변경 검사
            if (!currentLocation.continent.equals(previousLocation.continent)) {
                indicators.addIndicator("CONTINENT_CHANGE", 0.85,
                    "Continent changed from " + previousLocation.continent + " to " + currentLocation.continent);
                indicators.incrementScore(0.5);
            }
            
        } catch (Exception e) {
            log.error("Error checking geographic anomaly", e);
        }
    }
    
    /**
     * IP 주소에서 지리적 위치 추정
     * 
     * 실제 환경에서는 MaxMind GeoIP2나 ip-api.com 같은 서비스를 사용해야 합니다.
     * 현재는 IP 범위 기반 간단한 추정 로직을 구현합니다.
     */
    private GeoLocation estimateGeoLocation(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }
        
        // 내부 IP 처리
        if (isPrivateIp(ip)) {
            return new GeoLocation("Internal", "Internal", 0.0, 0.0);
        }
        
        // IP 주소 파싱
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        
        try {
            int firstOctet = Integer.parseInt(parts[0]);
            int secondOctet = Integer.parseInt(parts[1]);
            
            // 간단한 IP 범위 기반 지역 매핑 (실제로는 GeoIP 데이터베이스 사용 필요)
            // 이것은 예시이며, 실제 지리적 정확도는 낮습니다
            if (firstOctet >= 1 && firstOctet <= 50) {
                // 북미 지역 IP 범위 (예시)
                return new GeoLocation("North America", "United States", 40.7128, -74.0060); // New York
            } else if (firstOctet >= 51 && firstOctet <= 100) {
                // 유럽 지역 IP 범위 (예시)
                return new GeoLocation("Europe", "United Kingdom", 51.5074, -0.1278); // London
            } else if (firstOctet >= 101 && firstOctet <= 150) {
                // 아시아 지역 IP 범위 (예시)
                if (secondOctet >= 0 && secondOctet <= 100) {
                    return new GeoLocation("Asia", "South Korea", 37.5665, 126.9780); // Seoul
                } else {
                    return new GeoLocation("Asia", "Japan", 35.6762, 139.6503); // Tokyo
                }
            } else if (firstOctet >= 151 && firstOctet <= 200) {
                // 오세아니아 지역 IP 범위 (예시)
                return new GeoLocation("Oceania", "Australia", -33.8688, 151.2093); // Sydney
            } else {
                // 기타 지역
                return new GeoLocation("Other", "Unknown", 0.0, 0.0);
            }
            
        } catch (NumberFormatException e) {
            log.error("Invalid IP format: {}", ip);
            return null;
        }
    }
    
    /**
     * 사설 IP 주소 확인
     */
    private boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") || 
               ip.startsWith("172.16.") || 
               ip.startsWith("172.17.") || 
               ip.startsWith("172.18.") || 
               ip.startsWith("172.19.") || 
               ip.startsWith("172.20.") || 
               ip.startsWith("172.21.") || 
               ip.startsWith("172.22.") || 
               ip.startsWith("172.23.") || 
               ip.startsWith("172.24.") || 
               ip.startsWith("172.25.") || 
               ip.startsWith("172.26.") || 
               ip.startsWith("172.27.") || 
               ip.startsWith("172.28.") || 
               ip.startsWith("172.29.") || 
               ip.startsWith("172.30.") || 
               ip.startsWith("172.31.") || 
               ip.startsWith("192.168.") ||
               ip.startsWith("127.");
    }
    
    /**
     * 두 지점 간 거리 계산 (Haversine formula)
     */
    private double calculateDistance(GeoLocation loc1, GeoLocation loc2) {
        final double R = 6371; // 지구 반경 (km)
        
        double lat1Rad = Math.toRadians(loc1.latitude);
        double lat2Rad = Math.toRadians(loc2.latitude);
        double deltaLat = Math.toRadians(loc2.latitude - loc1.latitude);
        double deltaLon = Math.toRadians(loc2.longitude - loc1.longitude);
        
        double a = Math.sin(deltaLat/2) * Math.sin(deltaLat/2) +
                   Math.cos(lat1Rad) * Math.cos(lat2Rad) *
                   Math.sin(deltaLon/2) * Math.sin(deltaLon/2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        
        return R * c;
    }
    
    /**
     * 지리적 위치 정보 내부 클래스
     */
    private static class GeoLocation {
        final String continent;
        final String country;
        final double latitude;
        final double longitude;
        
        GeoLocation(String continent, String country, double latitude, double longitude) {
            this.continent = continent;
            this.country = country;
            this.latitude = latitude;
            this.longitude = longitude;
        }
    }
    
    /**
     * 현재 세션 컨텍스트 저장 (듀얼 모드: userId + sessionId)
     */
    private void saveCurrentContext(SecurityEvent event) {
        // userId 기반 저장 (Primary)
        if (event.hasUserId()) {
            updateUserContext(event);

            // 세션-사용자 매핑 저장
            if (event.getSessionId() != null) {
                String mappingKey = ZeroTrustRedisKeys.sessionToUser(event.getSessionId());
                redisTemplate.opsForValue().set(mappingKey, event.getUserId(), Duration.ofHours(24));
            }
        }
    }
    
    /**
     * 사용자 컨텍스트 업데이트 (Zero Trust 핵심)
     */
    private void updateUserContext(SecurityEvent event) {
        String userContextKey = ZeroTrustRedisKeys.userContext(event.getUserId());

        // 기존 사용자 컨텍스트 조회 또는 생성
        UserSecurityContext userContext = null;
        try {
            userContext = (UserSecurityContext) redisTemplate.opsForValue().get(userContextKey);
        } catch (org.springframework.dao.InvalidDataAccessApiUsageException e) {
            // WRONGTYPE 에러: 키가 다른 타입으로 저장되어 있음 (레거시 데이터)
            log.warn("Redis key type mismatch for userContext: {} - deleting legacy data", userContextKey);
            redisTemplate.delete(userContextKey);
        }

        if (userContext == null) {
            userContext = UserSecurityContext.builder()
                .userId(event.getUserId())
                .userName(event.getUserName())
                .currentThreatScore(0.5) // 기본 위협 점수
                .build();
        }
        
        // 세션 정보 추가/업데이트
        if (event.getSessionId() != null) {
            UserSecurityContext.SessionContext sessionContext = UserSecurityContext.SessionContext.builder()
                .sessionId(event.getSessionId())
                .sourceIp(event.getSourceIp())
                .userAgent(event.getUserAgent())
                .startTime(LocalDateTime.now())
                .lastAccessTime(LocalDateTime.now())
                .active(true)
                .build();

            userContext.addSession(sessionContext);
        }
        
        // 행동 패턴 업데이트
        userContext.addBehaviorPattern("lastEventType", event.getEventType().toString());
        userContext.addBehaviorPattern("lastSourceIp", event.getSourceIp());
        
        // 사용자 컨텍스트 저장 (30일 TTL)
        redisTemplate.opsForValue().set(userContextKey, userContext, Duration.ofDays(30));
        
        log.debug("Updated user context for userId: {}, sessionId: {}", 
            event.getUserId(), event.getSessionId());
    }
    
    /**
     * 사용자 컨텍스트에서 세션 정보 추출
     */
    private Map<Object, Object> extractSessionContext(UserSecurityContext userContext, String sessionId) {
        Map<Object, Object> context = new HashMap<>();
        
        if (userContext.getActiveSessions() != null) {
            userContext.getActiveSessions().stream()
                .filter(s -> s.getSessionId().equals(sessionId))
                .findFirst()
                .ifPresent(session -> {
                    context.put("sourceIp", session.getSourceIp());
                    context.put("userAgent", session.getUserAgent());
                    context.put("lastAccess", 
                        session.getLastAccessTime() != null ? 
                        session.getLastAccessTime().toEpochSecond(java.time.ZoneOffset.UTC) * 1000 : 
                        System.currentTimeMillis());
                    context.put("userId", userContext.getUserId());
                });
        }
        
        return context;
    }
    
    /**
     * AI Native v3.3.0: action 직접 결정
     *
     * 세션 위협 지표 기반으로 action을 결정합니다.
     * INVESTIGATE 제거 - 4개 Action만 허용 (ALLOW/BLOCK/CHALLENGE/ESCALATE)
     *
     * @param indicators 세션 위협 지표
     * @return action 문자열 (BLOCK, ESCALATE, CHALLENGE, ALLOW)
     */
    private String determineAction(SessionThreatIndicators indicators) {
        // 세션 무효화 필요 = 즉시 차단
        if (indicators.shouldInvalidateSession()) {
            return "BLOCK";
        }

        // 세션 하이재킹 의심 = 상위 계층 결정 위임
        // AI Native v3.3.0: INVESTIGATE 제거 -> ESCALATE
        if (indicators.isSessionHijackSuspected()) {
            return "ESCALATE";
        }

        // 의심스러운 활동 = MFA 요구
        if (indicators.isSuspiciousActivity()) {
            return "CHALLENGE";
        }

        // 정상
        return "ALLOW";
    }
    
    /**
     * SessionThreatIndicators를 ThreatIndicator 리스트로 변환
     */
    private List<ThreatIndicator> convertToThreatIndicators(SessionThreatIndicators indicators) {
        List<ThreatIndicator> threatIndicators = new ArrayList<>();
        
        indicators.getIndicators().forEach((key, value) -> {
            ThreatIndicator indicator = ThreatIndicator.builder()
                .type(mapToIndicatorType(key))
                .value(value)
                .confidence(0.8)
                .severity(ThreatIndicator.Severity.MEDIUM)
                .status(ThreatIndicator.IndicatorStatus.ACTIVE)
                .detectedAt(LocalDateTime.now())
                .build();
            threatIndicators.add(indicator);
        });
        
        return threatIndicators;
    }
    
    /**
     * 문자열 키를 IndicatorType으로 매핑
     */
    private ThreatIndicator.IndicatorType mapToIndicatorType(String key) {
        return switch (key) {
            case "IP_CHANGED" -> ThreatIndicator.IndicatorType.IP_ADDRESS;
            case "UA_CHANGED" -> ThreatIndicator.IndicatorType.USER_AGENT;
            case "RAPID_ACCESS" -> ThreatIndicator.IndicatorType.BEHAVIORAL;
            case "ERROR" -> ThreatIndicator.IndicatorType.EVENT;
            default -> ThreatIndicator.IndicatorType.UNKNOWN;
        };
    }
    
    /**
     * 권장 액션 생성
     */
    private List<String> generateRecommendedActions(SessionThreatIndicators indicators) {
        List<String> actions = new ArrayList<>();
        
        if (indicators.shouldInvalidateSession()) {
            actions.add("INVALIDATE_SESSION");
            actions.add("FORCE_REAUTHENTICATION");
        }
        
        if (indicators.isSessionHijackSuspected()) {
            actions.add("ALERT_USER");
            actions.add("LOG_SECURITY_INCIDENT");
            actions.add("ENABLE_STEP_UP_AUTH");
        }
        
        if (indicators.isIpChanged()) {
            actions.add("VERIFY_DEVICE");
        }
        
        if (indicators.isUserAgentChanged()) {
            actions.add("CHECK_BROWSER_FINGERPRINT");
        }
        
        actions.add("MONITOR_SESSION");
        
        return actions;
    }
    
    /**
     * 세션 무효화 이벤트 발행
     */
    private void publishSessionInvalidationEvent(SecurityEvent event, SessionThreatIndicators indicators) {
        try {
            Map<String, Object> invalidationEvent = new HashMap<>();
            invalidationEvent.put("sessionId", event.getSessionId());
            invalidationEvent.put("userId", event.getUserId());
            invalidationEvent.put("reason", indicators.isSuspiciousActivity() ? 
                "SUSPICIOUS_ACTIVITY" : "SESSION_HIJACK_SUSPECTED");
            invalidationEvent.put("detectedAt", System.currentTimeMillis());
            invalidationEvent.put("sourceIp", event.getSourceIp());
            invalidationEvent.put("userAgent", event.getUserAgent());
            invalidationEvent.put("riskScore", indicators.getAdditionalRisk());
            invalidationEvent.put("invalidateAllUserSessions", indicators.shouldInvalidateSession());
            invalidationEvent.put("indicators", indicators.getIndicators());
            
            // Redis Pub/Sub 으로 발행
            String eventJson = objectMapper.writeValueAsString(invalidationEvent);
            redisTemplate.convertAndSend(sessionHijackChannel, eventJson);
            
            log.info("Session invalidation event published: sessionId={}, userId={}, risk={}", 
                event.getSessionId(), event.getUserId(), indicators.getAdditionalRisk());
            
        } catch (Exception e) {
            log.error("Failed to publish session invalidation event", e);
        }
    }
    
    /**
     * 최소 평가 결과 생성 (세션 ID가 없는 경우)
     */
    private ThreatAssessment createMinimalAssessment(SecurityEvent event) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .riskScore(0.0)
            .indicators(new ArrayList<>())
            .recommendedActions(List.of("NO_SESSION_CONTEXT"))
            .confidence(0.1)
            .action("ALLOW")  // AI Native: action 직접 설정
            .build();
    }
    
    /**
     * 메타데이터 생성
     */
    private Map<String, Object> createMetadata(SessionThreatIndicators indicators) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("ipChanged", indicators.isIpChanged());
        metadata.put("userAgentChanged", indicators.isUserAgentChanged());
        metadata.put("suspiciousActivity", indicators.isSuspiciousActivity());
        metadata.put("sessionHijackSuspected", indicators.isSessionHijackSuspected());
        metadata.put("shouldInvalidate", indicators.shouldInvalidateSession());
        metadata.put("additionalRisk", indicators.getAdditionalRisk());
        return metadata;
    }
    
    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        if (event == null) {
            log.warn("SecurityEvent가 null입니다. 지표 추출을 건너뜁니다.");
            return new ArrayList<>();
        }
        
        try {
            SessionThreatIndicators indicators = analyzeSessionContext(event);
            return convertToThreatIndicators(indicators);
        } catch (Exception e) {
            log.error("세션 위협 지표 추출 중 오류 발생", e);
            return new ArrayList<>();
        }
    }
    
    @Override
    public String getStrategyName() {
        return "SESSION_THREAT_EVALUATION";
    }
    
    @Override
    public String getDescription() {
        return "Session threat evaluation strategy for detecting session hijacking, " +
               "session fixation, and other session-related threats";
    }

    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        SessionThreatIndicators indicators = analyzeSessionContext(event);
        return generateRecommendedActions(indicators);
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        if (indicators == null || indicators.isEmpty()) {
            return 0.0;
        }
        
        // 각 지표의 위험도를 합산
        double totalRisk = indicators.stream()
            .mapToDouble(indicator -> {
                // 지표 타입별 가중치 적용
                return switch (indicator.getType()) {
                    case IP_ADDRESS -> ipChangeRisk;
                    case USER_AGENT -> userAgentChangeRisk;
                    case BEHAVIORAL -> rapidAccessRisk;
                    default -> 0.1;
                };
            })
            .sum();
        
        return Math.min(1.0, totalRisk);
    }
    
    @Override
    public boolean canEvaluate(SecurityEvent.EventType eventType) {
        // 세션 관련 이벤트 타입만 처리
        return eventType == SecurityEvent.EventType.AUTH_SUCCESS ||
               eventType == SecurityEvent.EventType.AUTH_FAILURE ||
               eventType == SecurityEvent.EventType.ACCESS_VIOLATION ||
               eventType == SecurityEvent.EventType.SUSPICIOUS_ACTIVITY;
    }
    
    @Override
    public int getPriority() {
        return 50; // 중간 우선순위
    }

    /**
     * 세션 컨텍스트 기반 신뢰도 계산
     *
     * SessionThreatEvaluationStrategy는 LLM 없는 전통적 전략이므로
     * 세션 정보 유무에 따라 confidence를 자체 계산합니다.
     *
     * @param event 보안 이벤트
     * @return 신뢰도 점수 (0.5 ~ 1.0)
     */
    @Override
    public double calculateConfidenceScore(SecurityEvent event) {
        double confidence = 0.5;

        // 세션 정보 유무에 따른 신뢰도 증가
        if (event.getSessionId() != null) {
            confidence += 0.2;
        }
        if (event.getUserId() != null) {
            confidence += 0.1;
        }
        if (event.getSourceIp() != null) {
            confidence += 0.1;
        }
        if (event.getUserAgent() != null) {
            confidence += 0.1;
        }

        return Math.min(1.0, confidence);
    }
    
    /**
     * Zero Trust 아키텍처 - SecurityContext 기반 위협 평가 (기본 구현)
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
