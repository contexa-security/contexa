package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.hcad.domain.SecurityIncident;
import io.contexa.contexacore.hcad.domain.ThreatCorrelationResult;
import io.contexa.contexacore.hcad.domain.UserTrustProfile;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
/**
 * 위협 상관관계 분석 서비스
 *
 * ZeroTrustAdaptiveEngine에서 분리된 위협 상관관계 분석 전담 서비스
 * - 시간 기반 상관관계 분석
 * - IP 기반 상관관계 분석
 * - 행동 패턴 상관관계 분석
 * - 글로벌 위협 인텔리전스 연동
 */
@Slf4j
@RequiredArgsConstructor
public class ThreatCorrelationService {

    private final TimeSeriesCorrelationAnalyzer timeSeriesAnalyzer;

    @Value("${zerotrust.correlation.time-window-seconds:300}")
    private long threatCorrelationWindowSeconds;

    public ThreatCorrelationResult performThreatCorrelation(SecurityEvent event, UserTrustProfile trustProfile) {
        try {
            List<String> correlatedEvents = new ArrayList<>();
            List<String> suspiciousPatterns = new ArrayList<>();
            double correlationScore = 0.0;

            Instant windowStart = Instant.now().minusSeconds(threatCorrelationWindowSeconds);
            List<SecurityIncident> recentIncidents = trustProfile.getSecurityIncidents().stream()
                .filter(incident -> incident.getTimestamp().isAfter(windowStart))
                .collect(Collectors.toList());

            if (!recentIncidents.isEmpty()) {
                correlationScore += 0.3;
                correlatedEvents.addAll(recentIncidents.stream()
                    .map(SecurityIncident::getEventId)
                    .collect(Collectors.toList()));
            }

            String sourceIp = event.getSourceIp();
            if (sourceIp != null) {
                long sameIpCount = recentIncidents.stream()
                    .filter(incident -> sourceIp.equals(incident.getSourceIp()))
                    .count();

                if (sameIpCount > 1) {
                    correlationScore += 0.2;
                    suspiciousPatterns.add("REPEATED_IP_ACTIVITY");
                }
            }

            Map<String, Object> currentBehavior = extractBehaviorPattern(event);
            double behaviorSimilarity = calculateBehaviorSimilarity(currentBehavior, trustProfile.getBehaviorPatterns());

            if (behaviorSimilarity < 0.3) {
                correlationScore += 0.4;
                suspiciousPatterns.add("ANOMALOUS_BEHAVIOR");
            }

            // 🔥 시계열 상관관계 분석 추가 (APT 공격 탐지 강화)
            if (timeSeriesAnalyzer != null) {
                try {
                    // HCADContext 생성 (SecurityEvent → HCADContext 변환)
                    io.contexa.contexacommon.hcad.domain.HCADContext hcadContext =
                        convertSecurityEventToHCADContext(event);

                    double temporalAnomaly = timeSeriesAnalyzer.analyzeTemporalAnomaly(
                        event.getUserId(), hcadContext
                    );

                    if (temporalAnomaly > 0.7) {
                        correlationScore += 0.3;
                        suspiciousPatterns.add("TEMPORAL_ANOMALY");

                        if (log.isDebugEnabled()) {
                            log.debug("[ThreatCorrelation] Temporal anomaly detected - userId: {}, score: {:.3f}",
                                event.getUserId(), temporalAnomaly);
                        }
                    }

                } catch (Exception e) {
                    log.debug("[ThreatCorrelation] Temporal analysis failed: {}", e.getMessage());
                }
            }

            if (isGlobalThreatIndicator(event)) {
                correlationScore += 0.5;
                suspiciousPatterns.add("GLOBAL_THREAT_MATCH");
            }

            ThreatCorrelationResult result = ThreatCorrelationResult.builder()
                .correlatedEvents(correlatedEvents)
                .suspiciousPatterns(suspiciousPatterns)
                .correlationScore(Math.min(correlationScore, 1.0))
                .recentIncidentCount(recentIncidents.size())
                .behaviorSimilarity(behaviorSimilarity)
                .build();

            if (correlationScore > 0.5) {
                log.warn("[ThreatCorrelation] High correlation detected for user {}: score={}, patterns={}",
                        event.getUserId(), String.format("%.3f", correlationScore), suspiciousPatterns);
            }

            return result;

        } catch (Exception e) {
            log.error("[ThreatCorrelation] Analysis failed for event {}", event.getEventId(), e);
            return ThreatCorrelationResult.builder()
                .correlatedEvents(new ArrayList<>())
                .suspiciousPatterns(new ArrayList<>())
                .correlationScore(0.0)
                .recentIncidentCount(0)
                .behaviorSimilarity(1.0)
                .build();
        }
    }

    private Map<String, Object> extractBehaviorPattern(SecurityEvent event) {
        Map<String, Object> pattern = new java.util.HashMap<>();
        pattern.put("eventType", event.getEventType());
        pattern.put("sourceIp", event.getSourceIp());
        pattern.put("userAgent", event.getUserAgent());
        pattern.put("timestamp", event.getTimestamp());
        return pattern;
    }

    private double calculateBehaviorSimilarity(Map<String, Object> currentBehavior, Map<String, Object> baselinePatterns) {
        if (baselinePatterns.isEmpty()) {
            return 1.0;
        }

        int commonKeys = 0;
        double similarity = 0.0;

        for (String key : currentBehavior.keySet()) {
            if (baselinePatterns.containsKey(key)) {
                commonKeys++;
                Object currentValue = currentBehavior.get(key);
                Object baselineValue = baselinePatterns.get(key);

                if (currentValue != null && currentValue.equals(baselineValue)) {
                    similarity += 1.0;
                }
            }
        }

        return commonKeys > 0 ? similarity / commonKeys : 0.0;
    }

    private boolean isGlobalThreatIndicator(SecurityEvent event) {
        String sourceIp = event.getSourceIp();
        if (sourceIp != null) {
            return sourceIp.startsWith("192.168.") || sourceIp.startsWith("10.");
        }
        return false;
    }

    public void setTimeWindowSeconds(long seconds) {
        this.threatCorrelationWindowSeconds = seconds;
        log.info("[ThreatCorrelation] Time window set to {} seconds", seconds);
    }

    public boolean isHighCorrelation(double correlationScore) {
        return correlationScore > 0.7;
    }

    public String assessThreatLevel(ThreatCorrelationResult result) {
        int patternCount = result.getSuspiciousPatterns().size();
        double score = result.getCorrelationScore();

        if (score > 0.8 || patternCount >= 3) {
            return "CRITICAL";
        } else if (score > 0.6 || patternCount >= 2) {
            return "HIGH";
        } else if (score > 0.4 || patternCount >= 1) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }

    /**
     * SecurityEvent를 HCADContext로 변환
     *
     * SecurityEvent (자율 보안 시스템)의 정보를 HCAD 분석에 필요한 HCADContext 형식으로 변환합니다.
     *
     * @param event SecurityEvent 객체
     * @return HCADContext 객체
     */
    private io.contexa.contexacommon.hcad.domain.HCADContext convertSecurityEventToHCADContext(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("SecurityEvent cannot be null");
        }

        return io.contexa.contexacommon.hcad.domain.HCADContext.builder()
            // 사용자 식별 정보
            .userId(event.getUserId())
            .sessionId(event.getSessionId())
            .username(event.getUserName())

            // 요청 정보 (SecurityEvent는 HTTP 정보가 제한적이므로 메타데이터에서 추출)
            .requestPath(extractFromMetadata(event, "requestPath", event.getTargetResource()))
            .httpMethod(extractFromMetadata(event, "httpMethod", "SECURITY_EVENT"))
            .remoteIp(event.getSourceIp())
            .sourceIp(event.getSourceIp())
            .userAgent(event.getUserAgent())
            .referer(extractFromMetadata(event, "referer", null))
            .eventType(event.getEventType() != null ? event.getEventType().name() : "UNKNOWN")

            // 시간 정보
            .timestamp(event.getTimestamp() != null ?
                event.getTimestamp().atZone(java.time.ZoneId.systemDefault()).toInstant() :
                Instant.now())
            .requestTime(extractLongFromMetadata(event, "requestTime", null))

            // 보안 관련
            .authenticationMethod(extractFromMetadata(event, "authMethod", "unknown"))
            .failedLoginAttempts(extractIntFromMetadata(event, "failedAttempts", 0))
            .currentTrustScore(event.getConfidenceScore() != null ? event.getConfidenceScore() : 0.5)
            .trustScore(event.getConfidenceScore() != null ? event.getConfidenceScore() : 0.5)
            .hasValidMFA(extractBooleanFromMetadata(event, "mfaVerified", false))
            .riskScore(event.getRiskScore() != null ? event.getRiskScore().intValue() : null)
            .threatScore(event.getRiskScore())
            .anomalyScore(event.getHcadSimilarityScore() != null ?
                1.0 - event.getHcadSimilarityScore() : 0.5)

            // 리소스 접근 패턴
            .resourceType(extractResourceType(event))
            .isSensitiveResource(isSensitiveEvent(event))
            .previousPath(extractFromMetadata(event, "previousPath", null))

            // 행동 패턴
            .isNewSession(extractBooleanFromMetadata(event, "newSession", null))
            .isNewDevice(extractBooleanFromMetadata(event, "newDevice", null))
            .isNewLocation(extractBooleanFromMetadata(event, "newLocation", null))
            .recentRequestCount(extractIntFromMetadata(event, "recentRequests", null))
            .lastRequestInterval(extractLongFromMetadata(event, "lastInterval", null))

            // 추가 메타데이터
            .additionalAttributes(event.getMetadata())

            .build();
    }

    /**
     * 메타데이터에서 문자열 값 추출
     */
    private String extractFromMetadata(SecurityEvent event, String key, String defaultValue) {
        if (event.getMetadata() != null && event.getMetadata().containsKey(key)) {
            Object value = event.getMetadata().get(key);
            return value != null ? value.toString() : defaultValue;
        }
        return defaultValue;
    }

    /**
     * 메타데이터에서 Long 값 추출
     */
    private Long extractLongFromMetadata(SecurityEvent event, String key, Long defaultValue) {
        if (event.getMetadata() != null && event.getMetadata().containsKey(key)) {
            Object value = event.getMetadata().get(key);
            if (value instanceof Number) {
                return ((Number) value).longValue();
            }
            try {
                return Long.parseLong(value.toString());
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    /**
     * 메타데이터에서 Integer 값 추출
     */
    private Integer extractIntFromMetadata(SecurityEvent event, String key, Integer defaultValue) {
        if (event.getMetadata() != null && event.getMetadata().containsKey(key)) {
            Object value = event.getMetadata().get(key);
            if (value instanceof Number) {
                return ((Number) value).intValue();
            }
            try {
                return Integer.parseInt(value.toString());
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    /**
     * 메타데이터에서 Boolean 값 추출
     */
    private Boolean extractBooleanFromMetadata(SecurityEvent event, String key, Boolean defaultValue) {
        if (event.getMetadata() != null && event.getMetadata().containsKey(key)) {
            Object value = event.getMetadata().get(key);
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
            return Boolean.parseBoolean(value.toString());
        }
        return defaultValue;
    }

    /**
     * SecurityEvent로부터 리소스 타입 추출
     */
    private String extractResourceType(SecurityEvent event) {
        // 이벤트 타입 기반으로 리소스 타입 추정
        if (event.getEventType() == null) {
            return "general";
        }

        String eventTypeName = event.getEventType().name().toLowerCase();

        if (eventTypeName.contains("admin") || eventTypeName.contains("privilege")) {
            return "admin";
        } else if (eventTypeName.contains("api")) {
            return "api";
        } else if (eventTypeName.contains("auth") || eventTypeName.contains("credential")) {
            return "secure";
        } else if (eventTypeName.contains("system") || eventTypeName.contains("config")) {
            return "system";
        } else {
            return "general";
        }
    }

    /**
     * 민감한 이벤트 여부 판정
     */
    private boolean isSensitiveEvent(SecurityEvent event) {
        // 고위험 이벤트는 민감한 리소스로 간주
        if (event.isHighRisk()) {
            return true;
        }

        // 특정 이벤트 타입은 민감한 것으로 간주
        if (event.getEventType() != null) {
            String eventTypeName = event.getEventType().name();
            return eventTypeName.contains("ADMIN") ||
                   eventTypeName.contains("PRIVILEGE") ||
                   eventTypeName.contains("SYSTEM") ||
                   eventTypeName.contains("EXFILTRATION") ||
                   eventTypeName.contains("MALWARE") ||
                   eventTypeName.contains("COMPROMISE");
        }

        return false;
    }
}
