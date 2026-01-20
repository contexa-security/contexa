package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

/**
 * Zero Trust 이벤트 리스너 - ZeroTrustSpringEvent의 단일 수신점
 *
 * AI Native v14.0: ZeroTrustSpringEvent 전용 리스너
 *
 * 아키텍처:
 * 1. ZeroTrustEventPublisher가 ZeroTrustSpringEvent를 발행
 * 2. 이 리스너가 ZeroTrustSpringEvent만 수신
 * 3. 카테고리별 라우팅 후 Kafka 전송
 *
 * 플러그 앤 플레이:
 * - 애플리케이션은 ZeroTrustEventPublisher만 주입하여 이벤트 발행
 * - 이 리스너가 자동으로 수신하여 Zero Trust 처리
 *
 * 카테고리:
 * - AUTHENTICATION: 인증 이벤트
 * - AUTHORIZATION: 인가 이벤트
 * - SESSION: 세션 이벤트
 * - THREAT: 위협 탐지 이벤트
 * - CUSTOM: 애플리케이션 정의 이벤트
 *
 * @author contexa
 * @since 4.0.0
 */
@Slf4j
public class ZeroTrustEventListener {

    private final KafkaSecurityEventPublisher kafkaSecurityEventPublisher;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityDecisionPostProcessor postProcessor;

    @Value("${security.zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${security.zerotrust.sampling.rate:1.0}")
    private double samplingRate;

    public ZeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisTemplate<String, Object> redisTemplate,
            SecurityDecisionPostProcessor postProcessor) {
        this.kafkaSecurityEventPublisher = kafkaSecurityEventPublisher;
        this.redisTemplate = redisTemplate;
        this.postProcessor = postProcessor;
    }

    // ========== ZeroTrustSpringEvent 단일 진입점 ==========

    /**
     * Zero Trust 통합 이벤트 핸들러 - ZeroTrustSpringEvent의 유일한 수신점
     *
     * AI Native v14.0: 모든 이벤트가 이 핸들러를 통해 처리
     *
     * 이벤트 흐름:
     * 1. 애플리케이션 → ZeroTrustEventPublisher.publish*() 호출
     * 2. ZeroTrustEventPublisher → ZeroTrustSpringEvent 발행 (Spring Event)
     * 3. 이 핸들러 → ZeroTrustSpringEvent 수신
     * 4. 카테고리별 라우팅 → Kafka 전송
     *
     * @param event ZeroTrustSpringEvent
     */
    @EventListener
    public void handleZeroTrustEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            if (!zeroTrustEnabled) {
                log.debug("Zero Trust is disabled, skipping event processing");
                return;
            }

            // 카테고리 기반 라우팅
            switch (event.getCategory()) {
                case AUTHENTICATION:
                    processAuthenticationEvent(event);
                    break;
                case AUTHORIZATION:
                    processAuthorizationEvent(event);
                    break;
                case SESSION:
                    processSessionEvent(event);
                    break;
                case THREAT:
                    processThreatEvent(event);
                    break;
                case CUSTOM:
                    processCustomEvent(event);
                    break;
                default:
                    log.warn("[ZeroTrustEventListener] Unhandled event category: {}", event.getCategory());
            }

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[ZeroTrustEventListener] Event processed - category: {}, type: {}, duration: {}ms",
                    event.getCategory(), event.getEventType(), duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process event - category: {}, type: {}, duration: {}ms",
                    event.getCategory(), event.getEventType(), duration, e);
        }
    }

    // ========== 카테고리별 처리 메서드 ==========

    /**
     * 인증 이벤트 처리
     *
     * MFA 완료 케이스:
     * - LLM CHALLENGE/ESCALATE 후 MFA 완료 시
     * - Kafka 발행 없이 세션 컨텍스트만 업데이트
     *
     * 일반 케이스:
     * - Kafka로 이벤트 전송
     */
    private void processAuthenticationEvent(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();
        log.debug("[ZeroTrustEventListener] Processing authentication event - type: {}, user: {}",
                event.getEventType(), userId);

        // MFA 완료 케이스 확인 (LLM CHALLENGE/ESCALATE 후)
        if (ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS.equals(event.getEventType())) {
            if (isLlmChallengeMfa(userId)) {
                // MFA 완료: Kafka 발행 없이 세션 컨텍스트만 업데이트
                processMfaCompletion(event);
                return;
            }
        }

        // 일반 케이스: Kafka로 전송
        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * 인가 이벤트 처리
     *
     * 중복 분석 방지 (Redis 락)
     */
    private void processAuthorizationEvent(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();

        // 중복 분석 방지 (Redis 락)
        if (shouldSkipPublishing(userId)) {
            log.debug("[ZeroTrustEventListener] Skipping authorization event - analysis in progress for user: {}", userId);
            return;
        }

        log.debug("[ZeroTrustEventListener] Processing authorization event - type: {}, user: {}, resource: {}",
                event.getEventType(), userId, event.getResource());

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * 세션 이벤트 처리
     */
    private void processSessionEvent(ZeroTrustSpringEvent event) {
        log.debug("[ZeroTrustEventListener] Processing session event - type: {}, user: {}, session: {}",
                event.getEventType(), event.getUserId(), event.getSessionId());

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * 위협 탐지 이벤트 처리
     */
    private void processThreatEvent(ZeroTrustSpringEvent event) {
        log.warn("[ZeroTrustEventListener] Processing threat event - type: {}, user: {}, resource: {}",
                event.getEventType(), event.getUserId(), event.getResource());

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * CUSTOM 이벤트 처리
     */
    private void processCustomEvent(ZeroTrustSpringEvent event) {
        log.debug("[ZeroTrustEventListener] Processing custom event - type: {}, user: {}, payload keys: {}",
                event.getEventType(), event.getUserId(), event.getPayload().keySet());

        kafkaSecurityEventPublisher.publishGenericSecurityEvent(event);
    }

    // ========== MFA 관련 처리 ==========

    /**
     * LLM CHALLENGE/ESCALATE 후 MFA 완료 여부 확인
     *
     * @param userId 사용자 ID
     * @return MFA 완료 케이스 여부
     */
    private boolean isLlmChallengeMfa(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object previousAction = redisTemplate.opsForHash().get(analysisKey, "previousAction");

            String actionStr = String.valueOf(previousAction);
            boolean isLlmAction = "CHALLENGE".equals(actionStr) || "ESCALATE".equals(actionStr);

            if (isLlmAction) {
                redisTemplate.opsForHash().delete(analysisKey, "previousAction");
                log.debug("[ZeroTrustEventListener] LLM {} MFA confirmed - userId: {}", actionStr, userId);
            }

            return isLlmAction;

        } catch (Exception e) {
            log.debug("[ZeroTrustEventListener] MFA check failed - userId: {}", userId, e);
            return false;
        }
    }

    /**
     * MFA 완료 처리
     *
     * Kafka 발행 없이 세션 컨텍스트만 업데이트
     */
    private void processMfaCompletion(ZeroTrustSpringEvent event) {
        log.debug("[ZeroTrustEventListener] MFA completion processing - user: {}", event.getUserId());

        if (postProcessor != null) {
            SecurityEvent securityEvent = convertToSecurityEvent(event);
            SecurityDecision decision = createMfaSuccessDecision(event);

            postProcessor.updateSessionContext(securityEvent, decision);
            postProcessor.storeInVectorDatabase(securityEvent, decision);

            log.debug("[ZeroTrustEventListener] MFA verification completed - userId: {}", event.getUserId());
        }
    }

    /**
     * ZeroTrustSpringEvent를 SecurityEvent로 변환 (MFA 처리용)
     */
    private SecurityEvent convertToSecurityEvent(ZeroTrustSpringEvent event) {
        SecurityEvent securityEvent = new SecurityEvent();

        securityEvent.setEventId(event.getPayloadValue("eventId", java.util.UUID.randomUUID().toString()));
        securityEvent.setSource(SecurityEvent.EventSource.IAM);
        securityEvent.setTimestamp(LocalDateTime.ofInstant(event.getEventTimestamp(), ZoneId.systemDefault()));
        securityEvent.setUserId(event.getUserId());
        securityEvent.setUserName(event.getPayloadValue("userName"));
        securityEvent.setSessionId(event.getSessionId());
        securityEvent.setSourceIp(event.getClientIp());
        securityEvent.setUserAgent(event.getUserAgent());
        securityEvent.setSeverity(SecurityEvent.Severity.MEDIUM);

        Map<String, Object> metadata = new HashMap<>(event.getPayload());
        securityEvent.setMetadata(metadata);

        return securityEvent;
    }

    /**
     * MFA 성공 결정 생성
     */
    private SecurityDecision createMfaSuccessDecision(ZeroTrustSpringEvent event) {
        return SecurityDecision.builder()
                .action(SecurityDecision.Action.ALLOW)
                .riskScore(0.0)
                .confidence(1.0)
                .reasoning("MFA verification completed successfully")
                .eventId(event.getPayloadValue("eventId", java.util.UUID.randomUUID().toString()))
                .analysisTime(System.currentTimeMillis())
                .build();
    }

    // ========== 유틸리티 메서드 ==========

    /**
     * 중복 분석 방지를 위한 Redis 락 확인
     */
    private boolean shouldSkipPublishing(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Boolean isAnalyzing = redisTemplate.hasKey(analysisKey);

            if (Boolean.TRUE.equals(isAnalyzing)) {
                Long ttl = redisTemplate.getExpire(analysisKey);
                if (ttl != null && ttl > 0) {
                    log.debug("[ZeroTrustEventListener] Analysis in progress - userId: {}, TTL: {}s", userId, ttl);
                    return true;
                }
            }

            return false;

        } catch (Exception e) {
            log.debug("[ZeroTrustEventListener] Redis check failed, proceeding: {}", e.getMessage());
            return false;
        }
    }
}
