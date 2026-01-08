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
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.Duration;
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
public class ZeroTrustEventListener {

    private final KafkaSecurityEventPublisher kafkaSecurityEventPublisher;
    private final SecurityEventEnricher eventEnricher;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Phase 14: 분석 락 TTL (30초)
     * 동시 @Protectable 접근 시 중복 LLM 분석 방지
     */
    private static final Duration ANALYSIS_LOCK_TTL = Duration.ofSeconds(30);

    public ZeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            SecurityEventEnricher eventEnricher,
            RedisTemplate<String, Object> redisTemplate) {
        this.kafkaSecurityEventPublisher = kafkaSecurityEventPublisher;
        this.eventEnricher = eventEnricher;
        this.redisTemplate = redisTemplate;
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
     *
     * Phase 14: Redis SETNX 패턴으로 동시 LLM 분석 방지
     * 동일 사용자에 대해 여러 @Protectable 리소스 동시 접근 시
     * 첫 번째 요청만 LLM 분석을 트리거하고 나머지는 스킵
     */
    @EventListener
    public void handleAuthorizationDecision(AuthorizationDecisionEvent event) {
        long startTime = System.currentTimeMillis();
        try {
            if (!zeroTrustEnabled) {
                return;
            }

            String userId = event.getUserId();

            log.info("[ZeroTrustEventListener] Authorization decision event - user: {}, resource: {}, granted: {}",
                    userId, event.getResource(), event.isGranted());

            // Phase 14: Redis SETNX 패턴으로 중복 LLM 분석 방지
            if (userId != null && !userId.isEmpty() && !"anonymous".equals(userId)) {
                if (!tryAcquireAnalysisLock(userId)) {
                    log.debug("[ZeroTrustEventListener] Phase 14: LLM 분석 스킵 (이미 분석 중) - userId: {}, resource: {}",
                            userId, event.getResource());
                    return;
                }
            }

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
     * Phase 14: LLM 분석 락 획득 시도
     *
     * Redis SETNX 패턴으로 동시 분석 방지
     * - 락 획득 성공: true 반환 (분석 진행)
     * - 락 획득 실패: false 반환 (분석 스킵 - 이미 다른 요청이 분석 중)
     *
     * @param userId 사용자 ID
     * @return 락 획득 성공 여부
     */
    private boolean tryAcquireAnalysisLock(String userId) {
        try {
            // 캐시된 분석 결과가 유효한지 먼저 확인
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object existingAction = redisTemplate.opsForHash().get(analysisKey, "action");
            if (existingAction != null && !"PENDING_ANALYSIS".equals(existingAction.toString())) {
                // 이미 유효한 분석 결과 있음 - 재분석 불필요
                log.debug("[ZeroTrustEventListener] Phase 14: 유효한 분석 결과 존재 - userId: {}, action: {}",
                        userId, existingAction);
                return false;
            }

            // SETNX로 분석 락 획득 시도
            String lockKey = ZeroTrustRedisKeys.analysisLock(userId);
            Boolean acquired = redisTemplate.opsForValue()
                    .setIfAbsent(lockKey, "1", ANALYSIS_LOCK_TTL);

            if (Boolean.TRUE.equals(acquired)) {
                log.debug("[ZeroTrustEventListener] Phase 14: 분석 락 획득 성공 - userId: {}", userId);
                return true;
            } else {
                log.debug("[ZeroTrustEventListener] Phase 14: 분석 락 획득 실패 (이미 분석 중) - userId: {}", userId);
                return false;
            }

        } catch (Exception e) {
            log.warn("[ZeroTrustEventListener] Phase 14: 분석 락 확인 실패 - userId: {}, 분석 진행", userId, e);
            // Redis 오류 시 안전하게 분석 진행 (fail-open)
            return true;
        }
    }
    
    /**
     * AuthenticationFailureEvent를 SecurityEvent로 변환
     */
    private SecurityEvent convertAuthFailureToSecurityEvent(AuthenticationFailureEvent authEvent) {
        SecurityEvent event = new SecurityEvent();
        event.setEventId(authEvent.getEventId());
        // AI Native v4.0.0: eventType 제거 - severity, source로 분류
        event.setSource(SecurityEvent.EventSource.IAM);
        event.setUserId(authEvent.getUsername());
        event.setUserName(authEvent.getUsername());
        event.setTimestamp(authEvent.getEventTimestamp());
        event.setSourceIp(authEvent.getSourceIp());
        // AI Native v4.1.0: Severity 하드코딩 제거 - LLM이 원시 데이터로 직접 판단
        event.setSeverity(SecurityEvent.Severity.MEDIUM);

        Map<String, Object> metadata = new HashMap<>();
        // AI Native: 원시 데이터 제공 (LLM이 직접 위험도 평가)
        metadata.put("auth.failure_count", authEvent.getFailureCount());
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
        // AI Native v4.0.0: eventType 제거 - severity, source로 분류
        event.setSource(SecurityEvent.EventSource.IAM);
        event.setUserId(authEvent.getUserId());
        event.setUserName(authEvent.getUserId());
        event.setTimestamp(authEvent.getTimestamp() != null ?
                          LocalDateTime.ofInstant(authEvent.getTimestamp(), ZoneId.systemDefault()) :
                          LocalDateTime.now());
        event.setSourceIp(authEvent.getClientIp());
        // AI Native v4.1.0: Severity 하드코딩 제거 - LLM이 원시 데이터로 직접 판단
        event.setSeverity(SecurityEvent.Severity.MEDIUM);

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("resource", authEvent.getResource());
        metadata.put("action", authEvent.getAction());
        // AI Native: 원시 데이터 제공 (LLM이 granted 값을 보고 직접 판단)
        metadata.put("authz.granted", authEvent.isGranted());
        metadata.put("reason", authEvent.getReason());

        // AI Native v6.0: Zero Trust 핵심 신호 - 이벤트 필드에서 metadata로 복사
        // AuthorizationDecisionEvent의 isNew* 필드는 metadata가 아닌 별도 필드이므로 명시적 복사 필요
        if (authEvent.getIsNewSession() != null) {
            metadata.put("isNewSession", authEvent.getIsNewSession());
        }
        if (authEvent.getIsNewUser() != null) {
            metadata.put("isNewUser", authEvent.getIsNewUser());
        }
        if (authEvent.getIsNewDevice() != null) {
            metadata.put("isNewDevice", authEvent.getIsNewDevice());
        }
        if (authEvent.getRecentRequestCount() != null) {
            metadata.put("recentRequestCount", authEvent.getRecentRequestCount());
        }

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
        // AI Native v4.0.0: eventType 제거 - severity, source로 분류
        event.setSource(SecurityEvent.EventSource.IAM);
        event.setTimestamp(authEvent.getEventTimestamp());
        
        // 사용자 정보 (필수)
        event.setUserId(authEvent.getUserId());
        event.setUserName(authEvent.getUsername());
        event.setSessionId(authEvent.getSessionId());
        
        // 네트워크 정보
        event.setSourceIp(authEvent.getSourceIp());
        event.setUserAgent(authEvent.getUserAgent());

        // AI Native v4.1.0: Severity 매핑 제거 - LLM이 원시 데이터로 직접 판단
        event.setSeverity(SecurityEvent.Severity.MEDIUM);

        // 메타데이터
        Map<String, Object> metadata = new HashMap<>();

        // AI Native: 원시 데이터 제공 (LLM이 직접 위험도 평가)
        metadata.put("authz.trustScore", authEvent.getTrustScore());
        metadata.put("auth.riskLevel", authEvent.calculateRiskLevel().name());

        // 이상 징후 - metadata로 이동
        if (authEvent.isAnomalyDetected()) {
            metadata.put("auth.threatType", "ANOMALY_DETECTED");
            event.setBlocked(false); // 성공했지만 의심스러운 경우
        }
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
        // AI Native v6.0: httpMethod 제거 - LLM 분석에 불필요
        
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
            // AI Native v4.0.0: eventType 제거 - severity, source로 분류
            contextEvent.setSource(SecurityEvent.EventSource.IAM);
            contextEvent.setTimestamp(LocalDateTime.now());
            // AI Native v4.1.0: Severity 하드코딩 제거 - LLM이 원시 데이터로 직접 판단
            contextEvent.setSeverity(SecurityEvent.Severity.MEDIUM);
            
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
     * AI Native v4.1.0: 샘플링 제거 - 모든 이벤트 LLM 분석
     *
     * 이전: Risk Level, 이상 징후에 따른 조건부 샘플링
     * 변경: 모든 이벤트 100% LLM 분석 (필터링 없음)
     *
     * LLM이 원시 데이터를 보고 직접 위험도 판단
     */
    private boolean shouldProcessEvent(AuthenticationSuccessEvent event) {
        // AI Native: 모든 이벤트 처리 - LLM이 판단
        return true;
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

            // AI Native v4.1.0: 조건부 발행 제거 - 모든 이벤트 LLM 분석
            // 이전: EventTier/RiskScore 기반 조건부 발행 (CRITICAL/HIGH만)
            // 변경: 모든 이벤트 100% 발행 - LLM이 위험도 직접 판단
            boolean shouldPublish = true;
            String publishReason = "AI Native: All events forwarded for LLM analysis";

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
        secEvent.setUserAgent(event.getUserAgent());  // User-Agent 전달 (봇/정상 사용자 구별용)

        // AI Native v4.0.0: eventType 제거 - severity, source로 분류
        // 이벤트 source는 IAM으로 설정
        secEvent.setSource(SecurityEvent.EventSource.IAM);

        if (event.getUserId() != null && event.getUserId().startsWith("anonymous:")) {
            secEvent.setUserName("anonymous");
        } else {
            if (event.getAuthentication() != null) {
                secEvent.setUserName(event.getAuthentication().getName());
            }
        }

        // 메타데이터
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestUri", event.getRequestUri());
        metadata.put("httpMethod", event.getHttpMethod());
        metadata.put("statusCode", event.getStatusCode());

        // AI Native v4.3.0: 인증 방법 추가 (LLM 분석에 활용)
        if (event.getAuthMethod() != null) {
            metadata.put("authMethod", event.getAuthMethod());
        }

        // 통합 AI 분석 결과
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

        // Phase 9: 세션/사용자 컨텍스트 정보 추가 (Layer1 프롬프트 강화용)
        if (event.getIsNewSession() != null) {
            metadata.put("isNewSession", event.getIsNewSession());
        }
        if (event.getIsNewUser() != null) {
            metadata.put("isNewUser", event.getIsNewUser());
        }
        if (event.getIsNewDevice() != null) {
            metadata.put("isNewDevice", event.getIsNewDevice());
        }
        if (event.getRecentRequestCount() != null) {
            metadata.put("recentRequestCount", event.getRecentRequestCount());
        }

        // AI Native v4.1.0: 원시 데이터 추가 (LLM이 직접 판단)
        if (event.getRiskScore() != null) {
            metadata.put("authz.riskScore", event.getRiskScore());
        }
        if (event.getEventTier() != null) {
            metadata.put("event.tier", event.getEventTier().name());
        }
        secEvent.setMetadata(metadata);

        // AI Native v4.1.0: Severity 하드코딩 제거 - LLM이 원시 데이터로 직접 판단
        // 이전: Risk Score 임계값 기반 Severity 매핑 (0.8/0.6/0.4/0.2)
        // 변경: 기본값 MEDIUM, 원시 데이터(riskScore, eventTier)는 metadata에 저장
        secEvent.setSeverity(SecurityEvent.Severity.MEDIUM);

        return secEvent;
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