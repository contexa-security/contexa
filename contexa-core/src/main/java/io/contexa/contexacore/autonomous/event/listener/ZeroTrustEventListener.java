package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.event.domain.HttpRequestEvent;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.decision.EventTier;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static io.contexa.contexacore.autonomous.event.decision.EventTier.BENIGN;
import static io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent.ThreatLevel.*;

/**
 * Zero Trust 이벤트 리스너 (통합)
 *
 * Spring ApplicationEvent로 발행된 모든 Zero Trust 관련 이벤트를 수신하여
 * SecurityEvent로 변환 후 Kafka/Redis로 발행합니다.
 *
 * 처리하는 이벤트:
 * - AuthenticationSuccessEvent: 인증 성공
 * - AuthenticationFailureEvent: 인증 실패
 * - AuthorizationDecisionEvent: 권한 결정
 * - HttpRequestEvent: HTTP 요청 (NEW)
 */
@Slf4j
@Component
public class ZeroTrustEventListener {

    private final KafkaSecurityEventPublisher kafkaSecurityEventPublisher;
    private final SecurityEventEnricher eventEnricher;

    public ZeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            SecurityEventEnricher eventEnricher) {
        this.kafkaSecurityEventPublisher = kafkaSecurityEventPublisher;
        this.eventEnricher = eventEnricher;
    }
    
    @Value("${security.zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;
    
    @Value("${security.zerotrust.sampling.rate:1.0}")
    private double samplingRate;
    
    
    /**
     * 인증 성공 이벤트 처리
     *
     * Kafka 전송이 비동기이므로 @Async 제거하여 단순화
     * 로그인 응답 시간에 미치는 영향: ~1-2ms (Kafka 큐잉 시간)
     */
    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                log.debug("Zero Trust is disabled, skipping event processing");
                return;
            }

            // 샘플링 적용 (부하 관리)
            if (!shouldProcessEvent(event)) {
                log.debug("Event filtered by sampling for user: {}", event.getUsername());
                return;
            }

            // 이벤트 발행 (특화 메서드 사용 - 계층화된 토픽 분리 및 우선순위 처리)
            log.info("[ZeroTrustEventListener] Publishing authentication success event - EventID: {}, User: {}, SessionId: {}, Risk: {}",
                    event.getEventId(), event.getUsername(), event.getSessionId(), event.calculateRiskLevel());
            kafkaSecurityEventPublisher.publishAuthenticationSuccess(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] Event queued for Kafka successfully - EventID: {}, duration: {}ms",
                event.getEventId(), duration);

            // 성능 경고 (10ms 초과 시)
            if (duration > 10) {
                log.warn("[ZeroTrustEventListener] Event processing exceeded 10ms threshold: {}ms for user: {}",
                    duration, event.getUsername());
            }

            // 높은 위험도의 경우 즉시 세션 컨텍스트 소급
            if (event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.HIGH ||
                event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.CRITICAL) {
                publishSessionContextRetrospectively(event);
            }

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process authentication success event - duration: {}ms", duration, e);
            // 인증 성공은 계속 진행 (Zero Trust 이벤트만 유실)
        }
    }
    
    /**
     * 인증 실패 이벤트 처리
     */
    @EventListener
    public void handleAuthenticationFailure(AuthenticationFailureEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                return;
            }

            log.info("[ZeroTrustEventListener] Authentication failure event received - user: {}, attempts: {}",
                    event.getUsername(), event.getFailureCount());

            // 이벤트 발행 (특화 메서드 사용 - 브루트포스/크리덴셜 스터핑 감지 및 즉시 처리)
            kafkaSecurityEventPublisher.publishAuthenticationFailure(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] Auth failure event queued - EventID: {}, duration: {}ms",
                event.getEventId(), duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process authentication failure event - duration: {}ms", duration, e);
        }
    }
    
    /**
     * 권한 결정 이벤트 처리
     */
    @EventListener
    public void handleAuthorizationDecision(AuthorizationDecisionEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                return;
            }

            log.info("[ZeroTrustEventListener] Authorization decision event - user: {}, resource: {}, granted: {}",
                    event.getUserId(), event.getResource(), event.isGranted());

            // 이벤트 발행 (특화 메서드 사용 - 권한 부여/거부 패턴 분석 및 계층화 처리)
            kafkaSecurityEventPublisher.publishAuthorizationEvent(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] Authorization event queued - EventID: {}, duration: {}ms",
                event.getEventId(), duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process authorization decision event - duration: {}ms", duration, e);
        }
    }
    
    /**
     * AuthenticationFailureEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertAuthFailureToSecurityEvent(AuthenticationFailureEvent authEvent) {
        SecurityEvent event = new SecurityEvent();
        event.setEventId(authEvent.getEventId());
        event.setEventType(authEvent.getFailureCount() > 3 ?
                           SecurityEvent.EventType.BRUTE_FORCE :
                           SecurityEvent.EventType.AUTH_FAILURE);
        event.setUserId(authEvent.getUsername());
        event.setUserName(authEvent.getUsername());
        event.setTimestamp(authEvent.getEventTimestamp());
        event.setSourceIp(authEvent.getSourceIp());
        event.setSeverity(authEvent.getFailureCount() > 3 ?
                          SecurityEvent.Severity.HIGH :
                          SecurityEvent.Severity.MEDIUM);

        // HCAD 유사도 설정 (SecurityEvent 필드에만 저장, 메타데이터 중복 제거)
        if (authEvent.getHcadSimilarityScore() != null) {
            event.setHcadSimilarityScore(authEvent.getHcadSimilarityScore());
            log.debug("[ZeroTrust] HCAD similarity transferred from AuthenticationFailureEvent: user={}, score={}",
                     authEvent.getUsername(), String.format("%.3f", authEvent.getHcadSimilarityScore()));
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("failureCount", authEvent.getFailureCount());
        metadata.put("failureReason", authEvent.getFailureReason());

        event.setMetadata(metadata);

        return event;
    }
    
    /**
     * AuthorizationDecisionEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertAuthDecisionToSecurityEvent(AuthorizationDecisionEvent authEvent) {
        SecurityEvent event = new SecurityEvent();
        event.setEventId(authEvent.getEventId() != null ? authEvent.getEventId() : UUID.randomUUID().toString());
        event.setEventType(authEvent.isGranted() ?
                           SecurityEvent.EventType.AUTH_SUCCESS :
                           SecurityEvent.EventType.ACCESS_CONTROL_VIOLATION);
        event.setUserId(authEvent.getUserId());
        event.setUserName(authEvent.getUserId());
        event.setTimestamp(authEvent.getTimestamp() != null ?
                          LocalDateTime.ofInstant(authEvent.getTimestamp(), ZoneId.systemDefault()) :
                          LocalDateTime.now());
        event.setSourceIp(authEvent.getClientIp());
        event.setSeverity(authEvent.isGranted() ?
                          SecurityEvent.Severity.INFO :
                          SecurityEvent.Severity.MEDIUM);

        // HCAD 유사도 설정 (SecurityEvent 필드에만 저장, 메타데이터 중복 제거)
        if (authEvent.getHcadSimilarityScore() != null) {
            event.setHcadSimilarityScore(authEvent.getHcadSimilarityScore());
            log.debug("[ZeroTrust] HCAD similarity transferred from AuthorizationDecisionEvent: user={}, score={}",
                     authEvent.getUserId(), String.format("%.3f", authEvent.getHcadSimilarityScore()));
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("resource", authEvent.getResource());
        metadata.put("action", authEvent.getAction());
        metadata.put("granted", authEvent.isGranted());
        metadata.put("reason", authEvent.getReason());

        if (authEvent.getMetadata() != null) {
            metadata.putAll(authEvent.getMetadata());
        }
        event.setMetadata(metadata);

        return event;
    }
    
    /**
     * AuthenticationSuccessEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertToSecurityEvent(AuthenticationSuccessEvent authEvent) {
        SecurityEvent event = new SecurityEvent();
        
        event.setEventId(authEvent.getEventId());
        event.setEventType(SecurityEvent.EventType.AUTH_SUCCESS);
        event.setSource(SecurityEvent.EventSource.IAM);
        event.setTimestamp(authEvent.getEventTimestamp());
        
        // 사용자 정보 (필수)
        event.setUserId(authEvent.getUserId());
        event.setUserName(authEvent.getUsername());
        event.setSessionId(authEvent.getSessionId());
        
        // 네트워크 정보
        event.setSourceIp(authEvent.getSourceIp());
        event.setUserAgent(authEvent.getUserAgent());
        
        // 위험 평가
        event.setSeverity(mapRiskLevelToSeverity(authEvent.calculateRiskLevel()));
        event.setConfidenceScore(authEvent.getTrustScore());
        
        // 이상 징후
        if (authEvent.isAnomalyDetected()) {
            event.setThreatType("ANOMALY_DETECTED");
            event.setBlocked(false); // 성공했지만 의심스러운 경우
        }

        // HCAD 유사도 설정 (SecurityEvent 필드에만 저장, 메타데이터 중복 제거)
        if (authEvent.getHcadSimilarityScore() != null) {
            event.setHcadSimilarityScore(authEvent.getHcadSimilarityScore());
            log.debug("[ZeroTrust] HCAD similarity transferred to SecurityEvent: userId={}, score={}",
                     authEvent.getUserId(), String.format("%.3f", authEvent.getHcadSimilarityScore()));
        }

        // 메타데이터
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("authenticationType", authEvent.getAuthenticationType());
        metadata.put("mfaCompleted", authEvent.isMfaCompleted());
        metadata.put("mfaMethod", authEvent.getMfaMethod());
        metadata.put("deviceId", authEvent.getDeviceId());

        if (authEvent.getRiskIndicators() != null) {
            metadata.putAll(authEvent.getRiskIndicators());
        }
        if (authEvent.getMetadata() != null) {
            metadata.putAll(authEvent.getMetadata());
        }
        event.setMetadata(metadata);
        
        return event;
    }
    
    /**
     * SecurityEvent 메타데이터 보강
     */
    private void enrichSecurityEvent(SecurityEvent event, AuthenticationSuccessEvent authEvent) {
        // SecurityEventEnricher를 사용하여 추가 컨텍스트 정보 추가
        eventEnricher.setTargetResource(event, "/authentication/success");
        eventEnricher.setHttpMethod(event, "POST");
        
        // 사용자 행동 패턴 정보
        Map<String, Object> userBehavior = new HashMap<>();
        userBehavior.put("lastLoginTime", authEvent.getLastLoginTime());
        userBehavior.put("previousSessionId", authEvent.getPreviousSessionId());
        userBehavior.put("deviceId", authEvent.getDeviceId());
        eventEnricher.setUserBehavior(event, userBehavior);
        
        // 패턴 점수 계산
        double patternScore = calculatePatternScore(authEvent);
        eventEnricher.setPatternScore(event, patternScore);
        
        // 위험 지표 설정
        Map<String, Object> riskIndicators = new HashMap<>();
        riskIndicators.put("riskLevel", authEvent.calculateRiskLevel().toString());
        riskIndicators.put("anomalyDetected", authEvent.isAnomalyDetected());
        riskIndicators.put("trustScore", authEvent.getTrustScore());
        eventEnricher.setRiskIndicators(event, riskIndicators);
    }
    
    
    /**
     * 세션 컨텍스트 소급 발행
     * 
     * 이상 징후 발견시 해당 세션의 모든 이벤트를 소급하여 분석
     */
    private void publishSessionContextRetrospectively(AuthenticationSuccessEvent authEvent) {
        try {
            log.warn("High risk authentication detected for user: {}, publishing session context", 
                    authEvent.getUsername());
            
            // 세션 컨텍스트 이벤트 생성
            SecurityEvent contextEvent = new SecurityEvent();
            contextEvent.setEventId(UUID.randomUUID().toString());
            contextEvent.setEventType(SecurityEvent.EventType.SUSPICIOUS_ACTIVITY);
            contextEvent.setSource(SecurityEvent.EventSource.IAM);
            contextEvent.setTimestamp(LocalDateTime.now());
            contextEvent.setSeverity(SecurityEvent.Severity.HIGH);
            
            // 사용자 정보
            contextEvent.setUserId(authEvent.getUserId());
            contextEvent.setUserName(authEvent.getUsername());
            contextEvent.setSessionId(authEvent.getSessionId());
            
            // 세션 전체 컨텍스트
            Map<String, Object> fullContext = new HashMap<>();
            fullContext.put("originalEventId", authEvent.getEventId());
            fullContext.put("sessionContext", authEvent.getSessionContext());
            fullContext.put("riskIndicators", authEvent.getRiskIndicators());
            fullContext.put("anomalyDetected", authEvent.isAnomalyDetected());
            fullContext.put("trustScore", authEvent.getTrustScore());
            contextEvent.setMetadata(fullContext);

            // 우선순위 높게 발행
            kafkaSecurityEventPublisher.publishSecurityEvent(contextEvent);
            
        } catch (Exception e) {
            log.error("Failed to publish session context retrospectively", e);
        }
    }
    
    /**
     * 샘플링 결정
     */
    private boolean shouldProcessEvent(AuthenticationSuccessEvent event) {
        // 높은 위험도는 항상 처리
        if (event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.HIGH ||
            event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.CRITICAL ||
            event.isAnomalyDetected()) {
            return true;
        }
        
        // 샘플링 비율 적용
        return Math.random() < samplingRate;
    }
    
    /**
     * 패턴 점수 계산
     */
    private double calculatePatternScore(AuthenticationSuccessEvent event) {
        double score = 0.5; // 기본 점수
        
        // 신뢰 점수 반영
        if (event.getTrustScore() != null) {
            score = event.getTrustScore();
        }
        
        // MFA 완료시 점수 증가
        if (event.isMfaCompleted()) {
            score += 0.2;
        }
        
        // 이상 징후 발견시 점수 감소
        if (event.isAnomalyDetected()) {
            score -= 0.4;
        }
        
        return Math.max(0.0, Math.min(1.0, score));
    }
    
    /**
     * 위험 수준을 Severity로 매핑
     */
    private SecurityEvent.Severity mapRiskLevelToSeverity(AuthenticationSuccessEvent.RiskLevel riskLevel) {
        return switch (riskLevel) {
            case CRITICAL -> SecurityEvent.Severity.CRITICAL;
            case HIGH -> SecurityEvent.Severity.HIGH;
            case MEDIUM -> SecurityEvent.Severity.MEDIUM;
            case LOW -> SecurityEvent.Severity.LOW;
            case MINIMAL -> SecurityEvent.Severity.INFO;
            case UNKNOWN -> SecurityEvent.Severity.MEDIUM;
        };
    }

    /**
     * HTTP 요청 이벤트 처리 (조건부 발행)
     *
     * SecurityEventPublishingFilter가 샘플링한 이벤트 중에서
     * 실제 이상 징후가 있거나 CRITICAL/HIGH 위협만 Kafka/Redis로 발행합니다.
     *
     * 정상 요청 (BENIGN 샘플링)은 Session Context만 업데이트하고 발행하지 않아
     * 최종 발행 볼륨을 전체 요청의 1~5%로 감소시킵니다.
     */
    @EventListener
    @Async
    public void handleHttpRequest(HttpRequestEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                return;
            }

            log.debug("[ZeroTrustEventListener] HTTP request event received - userId: {}, uri: {}, tier: {}, risk: {}",
                    event.getUserId(), event.getRequestUri(),
                    event.getEventTier(), event.getRiskScore());

            // 1. Session Context 업데이트 (모든 샘플링된 이벤트)
            updateSessionContext(event);

            // 2. 조건부 발행: CRITICAL/HIGH 위협만 발행
            boolean shouldPublish = false;
            String publishReason = null;

            if (event.getEventTier() != null) {
                switch (event.getEventTier()) {
                    case CRITICAL:
                        shouldPublish = true;
                        publishReason = "CRITICAL tier - immediate threat";
                        break;
                    case HIGH:
                        shouldPublish = true;
                        publishReason = "HIGH tier - significant risk";
                        break;
                    case MEDIUM:
                        // MEDIUM은 Risk Score 0.6 이상만 발행
                        if (event.getRiskScore() != null && event.getRiskScore() >= 0.6) {
                            shouldPublish = true;
                            publishReason = "MEDIUM tier with high risk score";
                        }
                        break;
                    case LOW:
                    case BENIGN:
                        // LOW/BENIGN은 발행 안 함 (피드백 루프만)
                        shouldPublish = false;
                        break;
                }
            }

            if (!shouldPublish) {
                log.debug("[ZeroTrustEventListener] Event not published (tier: {}, reason: normal traffic) - SessionContext updated",
                         event.getEventTier());
                return;
            }

            // 3. 위협 레벨에 따라 적절한 메서드 사용
            if (event.getEventTier() == EventTier.CRITICAL) {
                // CRITICAL 위협 → publishThreatDetection 사용 (긴급 처리)
                ThreatDetectionEvent threatEvent = convertToThreatDetectionEvent(event, publishReason);
                kafkaSecurityEventPublisher.publishThreatDetection(threatEvent);

                log.warn("[ZeroTrustEventListener] CRITICAL threat published - EventID: {}, UserId: {}, Reason: {}",
                        threatEvent.getEventId(), event.getUserId(), publishReason);
            } else {
                // HIGH/MEDIUM → publishSecurityEvent 사용
                SecurityEvent securityEvent = convertHttpRequestToSecurityEvent(event);
                enrichSecurityEvent(securityEvent, event);
                kafkaSecurityEventPublisher.publishSecurityEvent(securityEvent);

                log.info("[ZeroTrustEventListener] Security event published - EventID: {}, UserId: {}, Tier: {}, Reason: {}",
                        securityEvent.getEventId(), event.getUserId(), event.getEventTier(), publishReason);
            }

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] HTTP request event processed - duration: {}ms", duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process HTTP request event - duration: {}ms", duration, e);
        }
    }

    /**
     * Session Context 업데이트
     * 정상 요청도 샘플링되므로 모든 샘플링 이벤트로 세션 컨텍스트를 구축합니다.
     */
    private void updateSessionContext(HttpRequestEvent event) {
        try {
            // Session Context Retrospective 구축
            // 여기서는 간단히 로깅만 하지만, 실제로는 세션 히스토리를 업데이트합니다
            log.trace("[ZeroTrustEventListener] SessionContext updated for user: {}", event.getUserId());

            // TODO: 실제 SessionContext 업데이트 로직 구현
            // - 세션별 요청 히스토리 추가
            // - 행동 패턴 분석
            // - 피드백 루프 연결 (정상 패턴 학습)
        } catch (Exception e) {
            log.warn("[ZeroTrustEventListener] Failed to update session context: {}", e.getMessage());
        }
    }

    /**
     * HttpRequestEvent를 ThreatDetectionEvent로 변환 (CRITICAL 위협용)
     */
    private ThreatDetectionEvent convertToThreatDetectionEvent(HttpRequestEvent event, String reason) {
        // 메타데이터 구성
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", event.getUserId());
        metadata.put("sourceIp", event.getSourceIp());
        metadata.put("requestUri", event.getRequestUri());
        metadata.put("httpMethod", event.getHttpMethod());
        metadata.put("eventTier", event.getEventTier().name());
        metadata.put("reason", reason);

        // HCAD 분석 결과 포함
        if (event.getHcadSimilarityScore() != null) {
            metadata.put("hcadSimilarity", event.getHcadSimilarityScore());
            metadata.put("anomalyScore", 1.0 - event.getHcadSimilarityScore());
        }

        if (event.getRiskScore() != null) {
            metadata.put("riskScore", event.getRiskScore());
        }

        if (event.getTrustScore() != null) {
            metadata.put("trustScore", event.getTrustScore());
        }

        // ThreatDetectionEvent 빌드
        return ThreatDetectionEvent.builder()
                .eventId(event.getEventId())
                .timestamp(event.getEventTimestamp().atZone(ZoneId.systemDefault()).toInstant())
                .threatType("HTTP_REQUEST_ANOMALY")
                .threatLevel(CRITICAL)
                .detectionSource("HCAD_FILTER")
                .confidenceScore(event.getRiskScore())
                .metadata(metadata)
                .build();
    }

    /**
     * HttpRequestEvent를 SecurityEvent로 변환 (통합 버전)
     *
     * AI 분석 결과를 SecurityEvent 메타데이터에 포함:
     * - HCAD 유사도 (AI 계산 결과)
     * - eventTier (Risk Score 기반 위험도 등급)
     * - riskScore (통합 위험도 점수)
     * - trustScore (인증 사용자 신뢰 점수)
     * - ipThreatScore (익명 사용자 IP 위협 점수)
     */
    private SecurityEvent convertHttpRequestToSecurityEvent(HttpRequestEvent event) {
        SecurityEvent secEvent = new SecurityEvent();
        secEvent.setEventId(event.getEventId());
        secEvent.setSource(SecurityEvent.EventSource.IAM);
        secEvent.setTimestamp(event.getEventTimestamp());

        // 사용자 정보
        secEvent.setUserId(event.getUserId());
        secEvent.setSourceIp(event.getSourceIp());

        // 이벤트 타입 결정 (익명 vs 인증)
        secEvent.setEventType(SecurityEvent.EventType.SUSPICIOUS_ACTIVITY);

        if (event.getUserId() != null && event.getUserId().startsWith("anonymous:")) {
            secEvent.setUserName("anonymous");
        } else {
            if (event.getAuthentication() != null) {
                secEvent.setUserName(event.getAuthentication().getName());
            }
        }

        // HCAD 유사도 점수 (AI 계산 결과)
        if (event.getHcadSimilarityScore() != null) {
            secEvent.setHcadSimilarityScore(event.getHcadSimilarityScore());
        }

        // 메타데이터
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestUri", event.getRequestUri());
        metadata.put("httpMethod", event.getHttpMethod());
        metadata.put("statusCode", event.getStatusCode());

        // AI 분석 결과 포함
        if (event.getHcadSimilarityScore() != null) {
            metadata.put("hcadSimilarityScore", event.getHcadSimilarityScore());
        }

        // 통합 AI 분석 결과 (NEW)
        if (event.getEventTier() != null) {
            metadata.put("eventTier", event.getEventTier().name());
            metadata.put("tierSamplingRate", event.getEventTier().getBaseSamplingRate());
        }

        if (event.getRiskScore() != null) {
            metadata.put("riskScore", event.getRiskScore());
        }

        if (event.isAnonymous()) {
            metadata.put("isAnonymous", true);

            // 익명 사용자 IP 위협 점수
            if (event.getIpThreatScore() != null) {
                metadata.put("ipThreatScore", event.getIpThreatScore());
                log.debug("[ZeroTrustEventListener] IP threat score from AI: {:.3f}",
                         event.getIpThreatScore());
            }
        } else {
            metadata.put("isAnonymous", false);

            // 인증 사용자 신뢰 점수
            if (event.getTrustScore() != null) {
                metadata.put("trustScore", event.getTrustScore());
                log.debug("[ZeroTrustEventListener] Trust score from AI: {:.3f}",
                         event.getTrustScore());
            }
        }

        secEvent.setMetadata(metadata);

        // 심각도 (통합 Risk Score 기반)
        if (event.getEventTier() != null) {
            secEvent.setSeverity(mapEventTierToSeverity(event.getEventTier()));
        } else if (event.getRiskScore() != null) {
            // Tier가 없으면 Risk Score로 직접 계산
            double risk = event.getRiskScore();
            if (risk > 0.8) {
                secEvent.setSeverity(SecurityEvent.Severity.CRITICAL);
            } else if (risk > 0.6) {
                secEvent.setSeverity(SecurityEvent.Severity.HIGH);
            } else if (risk > 0.4) {
                secEvent.setSeverity(SecurityEvent.Severity.MEDIUM);
            } else if (risk > 0.2) {
                secEvent.setSeverity(SecurityEvent.Severity.LOW);
            } else {
                secEvent.setSeverity(SecurityEvent.Severity.INFO);
            }
        } else {
            secEvent.setSeverity(SecurityEvent.Severity.MEDIUM);
        }

        return secEvent;
    }

    /**
     * EventTier를 Severity로 매핑 (통합 버전)
     *
     * @param tier AI 분류한 위험도 등급 (Risk Score 기반)
     * @return SecurityEvent Severity
     */
    private SecurityEvent.Severity mapEventTierToSeverity(EventTier tier) {
        return switch (tier) {
            case CRITICAL -> SecurityEvent.Severity.CRITICAL;
            case HIGH -> SecurityEvent.Severity.HIGH;
            case MEDIUM -> SecurityEvent.Severity.MEDIUM;
            case LOW -> SecurityEvent.Severity.LOW;
            case BENIGN -> SecurityEvent.Severity.INFO;
        };
    }

    /**
     * HttpRequestEvent로 SecurityEvent 보강
     */
    private void enrichSecurityEvent(SecurityEvent secEvent, HttpRequestEvent httpEvent) {
        // 기존 enrichSecurityEvent 메서드와 유사하지만 HttpRequestEvent 전용
        if (eventEnricher != null) {
            // SecurityEventEnricher 활용 (있는 경우)
            // 추가 컨텍스트 정보 보강
        }
    }

}