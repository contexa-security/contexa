package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * SecurityDecision 후처리 서비스
 *
 * AI Native v6.8: Layer1ContextualStrategy와 ZeroTrustEventListener에서 공통으로 사용하는
 * 세션 컨텍스트 업데이트 및 벡터 스토어 저장 로직을 통합합니다.
 *
 * 핵심 기능:
 * - updateSessionContext(): 세션 액션 히스토리에 판정 결과 기록
 * - storeInVectorDatabase(): ALLOW 판정 시 행동 패턴을 벡터 스토어에 저장
 *
 * AI Native 원칙:
 * - ALLOW만 저장 (RAG Pollution 방지)
 * - BLOCK은 위협 패턴으로 추가 저장
 * - CHALLENGE/ESCALATE는 저장하지 않음
 *
 * @author contexa
 * @since AI Native v6.8
 */
@Slf4j
public class SecurityDecisionPostProcessor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final UnifiedVectorService unifiedVectorService;

    public SecurityDecisionPostProcessor(
            RedisTemplate<String, Object> redisTemplate,
            UnifiedVectorService unifiedVectorService) {
        this.redisTemplate = redisTemplate;
        this.unifiedVectorService = unifiedVectorService;
    }

    /**
     * 세션 컨텍스트 업데이트
     *
     * Layer1ContextualStrategy.updateSessionContext()와 동일한 로직입니다.
     * 세션 액션 히스토리에 행동 기록을 추가하고, BLOCK 시 위험 점수를 저장합니다.
     *
     * @param event SecurityEvent
     * @param decision SecurityDecision
     */
    public void updateSessionContext(SecurityEvent event, SecurityDecision decision) {
        String sessionId = event.getSessionId();
        if (sessionId == null || redisTemplate == null) {
            return;
        }

        try {
            // AI Native v6.0: 행동 기반 세션 기록 (httpMethod 제거 - LLM 분석에 불필요)
            redisTemplate.opsForList().rightPush(
                    ZeroTrustRedisKeys.sessionActions(sessionId),
                    String.format("%s:%s",
                            event.getDescription() != null ? event.getDescription() : "action",
                            decision.getAction())
            );

            // v3.1.0: MITIGATE -> BLOCK으로 통합됨
            SecurityDecision.Action sessionAction = decision.getAction();
            if (sessionAction == SecurityDecision.Action.BLOCK) {
                redisTemplate.opsForValue().set(
                        ZeroTrustRedisKeys.sessionRisk(sessionId),
                        decision.getRiskScore(),
                        Duration.ofHours(1)
                );
            }

            log.debug("[SecurityDecisionPostProcessor] 세션 컨텍스트 업데이트 완료: sessionId={}, action={}",
                sessionId, decision.getAction());

        } catch (Exception e) {
            log.debug("[SecurityDecisionPostProcessor] 세션 컨텍스트 업데이트 실패: sessionId={}", sessionId, e);
        }
    }

    /**
     * Vector Store 저장
     *
     * Layer1ContextualStrategy.storeInVectorDatabase()와 동일한 로직입니다.
     *
     * AI Native v6.0: 모든 판정에 대해 행동 패턴 저장
     * - ALLOW: 정상 행동 패턴 학습용 BEHAVIOR 문서 저장
     * - BLOCK: 위협 패턴 학습용 THREAT 문서 추가 저장
     * - CHALLENGE/ESCALATE: 저장하지 않음 (RAG Pollution 방지)
     *
     * @param event SecurityEvent
     * @param decision SecurityDecision
     */
    public void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null) {
            return;
        }

        double confidence = decision.getConfidence();
        if (Double.isNaN(confidence)) {
            log.debug("[SecurityDecisionPostProcessor] confidence 없음, 벡터 저장 생략: eventId={}",
                event.getEventId());
            return;
        }

        try {
            SecurityDecision.Action action = decision.getAction();

            // AI Native v6.0: ALLOW만 저장 (Baseline 학습과 일관성 유지)
            // CHALLENGE/ESCALATE 저장 시 RAG 오염 발생 - 부정적 컨텍스트가 LLM에 전달됨
            if (action == SecurityDecision.Action.ALLOW) {
                storeBehaviorDocument(event, decision);
            }

            // BLOCK 판정: 위협 패턴으로 저장
            if (action == SecurityDecision.Action.BLOCK) {
                storeBehaviorDocument(event, decision);
                String content = buildBehaviorContent(event, decision);
                storeThreatDocument(event, decision, content);
            }

        } catch (Exception e) {
            log.debug("[SecurityDecisionPostProcessor] 벡터 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * 행동 패턴 문서 저장
     *
     * Layer1ContextualStrategy.storeBehaviorDocument()와 동일한 로직입니다.
     */
    private void storeBehaviorDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildBehaviorContent(event, decision);
            Map<String, Object> metadata = buildBaseMetadata(event, decision, VectorDocumentType.BEHAVIOR.getValue());

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

            log.debug("[SecurityDecisionPostProcessor] 행동 패턴 저장 완료: userId={}, action={}, riskScore={}",
                event.getUserId(), decision.getAction(), decision.getRiskScore());

        } catch (Exception e) {
            log.debug("[SecurityDecisionPostProcessor] 행동 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * 행동 패턴 컨텐츠 생성
     *
     * Layer1ContextualStrategy.buildBehaviorContent()와 동일한 로직입니다.
     */
    private String buildBehaviorContent(SecurityEvent event, SecurityDecision decision) {
        return String.format(
                "User: %s, Risk: %.2f, Description: %s, Reasoning: %s",
                event.getUserId() != null ? event.getUserId() : "unknown",
                decision.getRiskScore(),
                event.getDescription() != null ? event.getDescription() : "unknown",
                decision.getReasoning() != null ? decision.getReasoning() : "No reasoning provided"
        );
    }

    /**
     * 위협 문서 저장
     *
     * Layer1ContextualStrategy.storeThreatDocument()와 동일한 로직입니다.
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = buildBaseMetadata(event, decision, VectorDocumentType.THREAT.getValue());

            // 행동 패턴 추가
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatMetadata.put("behaviorPatterns", String.join(", ", decision.getBehaviorPatterns()));
            }

            // 위협 설명
            String threatDescription = String.format(
                "Contextual Threat: User=%s, IP=%s, RiskScore=%.2f, " +
                "ThreatCategory=%s, BehaviorPatterns=%s, Action=%s, Reasoning=%s",
                event.getUserId(), event.getSourceIp(),
                decision.getRiskScore(), decision.getThreatCategory(),
                decision.getBehaviorPatterns() != null ? decision.getBehaviorPatterns() : "[]",
                decision.getAction(),
                decision.getReasoning() != null ? decision.getReasoning().substring(0, Math.min(100, decision.getReasoning().length())) : ""
            );

            Document threatDoc = new Document(threatDescription, threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[SecurityDecisionPostProcessor] 위협 패턴 저장 완료: userId={}, riskScore={}, threatCategory={}",
                event.getUserId(), decision.getRiskScore(), decision.getThreatCategory());

        } catch (Exception e) {
            log.warn("[SecurityDecisionPostProcessor] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * 벡터 저장용 공통 메타데이터 생성
     *
     * AbstractTieredStrategy.buildBaseMetadata()와 동일한 로직입니다.
     *
     * AI Native 원칙:
     * - null인 경우 필드 생략 (LLM이 "unknown"을 실제 값으로 오해 방지)
     * - NaN인 경우 필드 생략 (LLM이 -1.0을 낮은 값으로 오해 방지)
     */
    private Map<String, Object> buildBaseMetadata(SecurityEvent event, SecurityDecision decision, String documentType) {
        Map<String, Object> metadata = new HashMap<>();

        // 필수 공통 metadata
        metadata.put("documentType", documentType);
        // AI Native v6.0 Critical: 이벤트 발생 시간 사용 (저장 시간 X)
        String eventTimestamp = event.getTimestamp() != null
            ? event.getTimestamp().toString()
            : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        metadata.put("timestamp", eventTimestamp);

        // SecurityEvent 정보 - AI Native: null인 경우 필드 생략
        if (event.getEventId() != null) {
            metadata.put("eventId", event.getEventId());
        }
        if (event.getUserId() != null) {
            metadata.put("userId", event.getUserId());
        }
        if (event.getSourceIp() != null) {
            metadata.put("sourceIp", event.getSourceIp());
        }
        if (event.getSessionId() != null) {
            metadata.put("sessionId", event.getSessionId());
        }

        // SecurityDecision 정보 - AI Native: NaN인 경우 필드 생략
        double riskScore = decision.getRiskScore();
        double confidence = decision.getConfidence();
        if (!Double.isNaN(riskScore)) {
            metadata.put("riskScore", riskScore);
        }
        if (!Double.isNaN(confidence)) {
            metadata.put("confidence", confidence);
        }
        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        return metadata;
    }
}
