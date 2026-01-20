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
        
        
        if (event.getSessionId() == null) {
            return createMinimalAssessment(event);
        }
        
        
        SessionThreatIndicators indicators = analyzeSessionContext(event);

        
        List<ThreatIndicator> threatIndicatorObjects = convertToThreatIndicators(indicators);

        
        List<String> threatIndicatorStrings = indicators.getIndicators().entrySet().stream()
            .map(e -> e.getKey() + ": " + e.getValue())
            .collect(Collectors.toList());

        
        List<String> recommendedActions = generateRecommendedActions(indicators);

        
        String action = determineAction(indicators);

        
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
            
            .action(action)  
            .build();
    }
    
    
    private SessionThreatIndicators analyzeSessionContext(SecurityEvent event) {
        SessionThreatIndicators indicators = new SessionThreatIndicators();
        
        try {
            
            Map<Object, Object> previousContext = null;
            
            if (event.hasUserId()) {
                
                String userContextKey = ZeroTrustRedisKeys.userContext(event.getUserId());
                try {
                    UserSecurityContext userContext = (UserSecurityContext) redisTemplate.opsForValue().get(userContextKey);

                    if (userContext != null && event.getSessionId() != null) {
                        
                        previousContext = extractSessionContext(userContext, event.getSessionId());
                    }
                } catch (org.springframework.dao.InvalidDataAccessApiUsageException e) {
                    
                    log.warn("Redis key type mismatch for userContext: {} - deleting legacy data", userContextKey);
                    redisTemplate.delete(userContextKey);
                }
            }

            
            
            

            if (previousContext != null && !previousContext.isEmpty()) {
                
                checkIpChange(event, previousContext, indicators);
                
                
                checkUserAgentChange(event, previousContext, indicators);
                
                
                checkTimePattern(event, previousContext, indicators);
                
                
                checkGeographicAnomaly(event, previousContext, indicators);
            }
            
            
            saveCurrentContext(event);
            
        } catch (Exception e) {
            log.error("Failed to analyze session context", e);
            indicators.addIndicator("ERROR", "Context analysis failed: " + e.getMessage());
        }
        
        return indicators;
    }
    
    
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
    
    
    private void checkGeographicAnomaly(SecurityEvent event, Map<Object, Object> previousContext,
                                       SessionThreatIndicators indicators) {
        
        String currentIp = event.getSourceIp();
        String previousIp = (String) previousContext.get("sourceIp");
        
        if (currentIp == null || previousIp == null) {
            return;
        }
        
        try {
            
            GeoLocation currentLocation = estimateGeoLocation(currentIp);
            GeoLocation previousLocation = estimateGeoLocation(previousIp);
            
            if (currentLocation == null || previousLocation == null) {
                return;
            }
            
            
            double distance = calculateDistance(previousLocation, currentLocation);

            
            LocalDateTime previousTime = (LocalDateTime) previousContext.get("timestamp");
            LocalDateTime currentTime = event.getTimestamp();

            if (previousTime == null || currentTime == null) {
                return;
            }

            long timeDiffMinutes = Duration.between(previousTime, currentTime).toMinutes();
            
            
            double maxPossibleDistance = timeDiffMinutes * 20.0; 
            
            if (distance > maxPossibleDistance) {
                indicators.addIndicator("IMPOSSIBLE_TRAVEL", 0.95, 
                    String.format("Impossible travel detected: %.2f km in %d minutes", 
                        distance, timeDiffMinutes));
                indicators.incrementScore(0.8);
                log.warn("Impossible travel detected for user {}: {} -> {} ({} km in {} min)",
                    event.getUserId(), previousIp, currentIp, distance, timeDiffMinutes);
            }
            
            
            if (!currentLocation.country.equals(previousLocation.country)) {
                indicators.addIndicator("COUNTRY_CHANGE", 0.7,
                    "Country changed from " + previousLocation.country + " to " + currentLocation.country);
                indicators.incrementScore(0.3);
            }
            
            
            if (!currentLocation.continent.equals(previousLocation.continent)) {
                indicators.addIndicator("CONTINENT_CHANGE", 0.85,
                    "Continent changed from " + previousLocation.continent + " to " + currentLocation.continent);
                indicators.incrementScore(0.5);
            }
            
        } catch (Exception e) {
            log.error("Error checking geographic anomaly", e);
        }
    }
    
    
    private GeoLocation estimateGeoLocation(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }
        
        
        if (isPrivateIp(ip)) {
            return new GeoLocation("Internal", "Internal", 0.0, 0.0);
        }
        
        
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        
        try {
            int firstOctet = Integer.parseInt(parts[0]);
            int secondOctet = Integer.parseInt(parts[1]);
            
            
            
            if (firstOctet >= 1 && firstOctet <= 50) {
                
                return new GeoLocation("North America", "United States", 40.7128, -74.0060); 
            } else if (firstOctet >= 51 && firstOctet <= 100) {
                
                return new GeoLocation("Europe", "United Kingdom", 51.5074, -0.1278); 
            } else if (firstOctet >= 101 && firstOctet <= 150) {
                
                if (secondOctet >= 0 && secondOctet <= 100) {
                    return new GeoLocation("Asia", "South Korea", 37.5665, 126.9780); 
                } else {
                    return new GeoLocation("Asia", "Japan", 35.6762, 139.6503); 
                }
            } else if (firstOctet >= 151 && firstOctet <= 200) {
                
                return new GeoLocation("Oceania", "Australia", -33.8688, 151.2093); 
            } else {
                
                return new GeoLocation("Other", "Unknown", 0.0, 0.0);
            }
            
        } catch (NumberFormatException e) {
            log.error("Invalid IP format: {}", ip);
            return null;
        }
    }
    
    
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
    
    
    private double calculateDistance(GeoLocation loc1, GeoLocation loc2) {
        final double R = 6371; 
        
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
    
    
    private void saveCurrentContext(SecurityEvent event) {
        
        if (event.hasUserId()) {
            updateUserContext(event);

            
            if (event.getSessionId() != null) {
                String mappingKey = ZeroTrustRedisKeys.sessionToUser(event.getSessionId());
                redisTemplate.opsForValue().set(mappingKey, event.getUserId(), Duration.ofHours(24));
            }
        }
    }
    
    
    private void updateUserContext(SecurityEvent event) {
        String userContextKey = ZeroTrustRedisKeys.userContext(event.getUserId());

        
        UserSecurityContext userContext = null;
        try {
            userContext = (UserSecurityContext) redisTemplate.opsForValue().get(userContextKey);
        } catch (org.springframework.dao.InvalidDataAccessApiUsageException e) {
            
            log.warn("Redis key type mismatch for userContext: {} - deleting legacy data", userContextKey);
            redisTemplate.delete(userContextKey);
        }

        if (userContext == null) {
            userContext = UserSecurityContext.builder()
                .userId(event.getUserId())
                .userName(event.getUserName())
                .currentThreatScore(0.5) 
                .build();
        }
        
        
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
        
        
        
        userContext.addBehaviorPattern("lastSeverity", event.getSeverity() != null ? event.getSeverity().toString() : "INFO");
        userContext.addBehaviorPattern("lastSourceIp", event.getSourceIp());
        
        
        redisTemplate.opsForValue().set(userContextKey, userContext, Duration.ofDays(30));
        
        log.debug("Updated user context for userId: {}, sessionId: {}", 
            event.getUserId(), event.getSessionId());
    }
    
    
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
    
    
    private String determineAction(SessionThreatIndicators indicators) {
        
        if (indicators.shouldInvalidateSession()) {
            return "BLOCK";
        }

        
        
        if (indicators.isSessionHijackSuspected()) {
            return "ESCALATE";
        }

        
        if (indicators.isSuspiciousActivity()) {
            return "CHALLENGE";
        }

        
        return "ALLOW";
    }
    
    
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
    
    
    private ThreatIndicator.IndicatorType mapToIndicatorType(String key) {
        return switch (key) {
            case "IP_CHANGED" -> ThreatIndicator.IndicatorType.IP_ADDRESS;
            case "UA_CHANGED" -> ThreatIndicator.IndicatorType.USER_AGENT;
            case "RAPID_ACCESS" -> ThreatIndicator.IndicatorType.BEHAVIORAL;
            case "ERROR" -> ThreatIndicator.IndicatorType.EVENT;
            default -> ThreatIndicator.IndicatorType.UNKNOWN;
        };
    }
    
    
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
            
            
            String eventJson = objectMapper.writeValueAsString(invalidationEvent);
            redisTemplate.convertAndSend(sessionHijackChannel, eventJson);
            
            log.info("Session invalidation event published: sessionId={}, userId={}, risk={}", 
                event.getSessionId(), event.getUserId(), indicators.getAdditionalRisk());
            
        } catch (Exception e) {
            log.error("Failed to publish session invalidation event", e);
        }
    }
    
    
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
            .action("ALLOW")  
            .build();
    }
    
    
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
        
        
        double totalRisk = indicators.stream()
            .mapToDouble(indicator -> {
                
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
    public boolean canEvaluate(SecurityEvent.Severity severity) {
        
        
        return true;
    }
    
    @Override
    public int getPriority() {
        return 50; 
    }

    
    @Override
    public double calculateConfidenceScore(SecurityEvent event) {
        double confidence = 0.5;

        
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
    
    
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
