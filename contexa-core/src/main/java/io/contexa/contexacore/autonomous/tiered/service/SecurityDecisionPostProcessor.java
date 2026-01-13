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

        try {
            SecurityDecision.Action action = decision.getAction();

            // AI Native v7.0: confidence NaN 처리 개선
            // 기존: NaN이면 저장 스킵 → ALLOW도 저장 안 됨 → Baseline 구축 불가
            // 변경: NaN이어도 ALLOW/BLOCK은 저장 (confidence 0.5 기본값 사용)
            double confidence = decision.getConfidence();
            if (Double.isNaN(confidence)) {
                log.debug("[SecurityDecisionPostProcessor] confidence NaN, 기본값 0.5 사용: eventId={}",
                    event.getEventId());
                // decision 객체의 confidence를 직접 수정하지 않고, 저장 시에만 0.5 사용
            }

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
     * AI Native v6.7: 순환 로직 방지
     * - LLM 결과(riskScore, reasoning) 제거 - 이전 분석이 다음 분석에 영향을 미치면 안 됨
     * - "unknown" 기본값 제거 - LLM이 실제 값으로 오해, 벡터 임베딩 오염
     * - 사실 데이터만 포함 (userId, IP, path, hour)
     */
    private String buildBehaviorContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder content = new StringBuilder();

        // 사용자 ID (null이면 생략)
        if (event.getUserId() != null) {
            content.append("User: ").append(event.getUserId());
        }

        // IP (사실 데이터)
        if (event.getSourceIp() != null) {
            if (content.length() > 0) content.append(", ");
            content.append("IP: ").append(event.getSourceIp());
        }

        // 경로 추출 (사실 데이터)
        String path = extractPath(event);
        if (path != null) {
            if (content.length() > 0) content.append(", ");
            content.append("Path: ").append(path);
        }

        // AI Native v7.0: HTTP Method 추가 (사실 데이터)
        String method = extractHttpMethod(event);
        if (method != null) {
            if (content.length() > 0) content.append(", ");
            content.append("Method: ").append(method);
        }

        // 시간 (사실 데이터)
        if (event.getTimestamp() != null) {
            if (content.length() > 0) content.append(", ");
            content.append("Hour: ").append(event.getTimestamp().getHour());
        }

        // AI Native v7.0: action 제거 (LLM 결과 = 순환 로직 위험)
        // - 이전 BLOCK/ALLOW가 embedding에 포함되면 다음 판단에 편향을 줄 수 있음

        return content.toString();
    }

    /**
     * HTTP Method 추출
     *
     * AI Native v7.0: metadata에서 httpMethod 추출
     * ZeroTrustEventListener에서 metadata.put("httpMethod", event.getHttpMethod())로 설정됨
     */
    private String extractHttpMethod(SecurityEvent event) {
        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;
            Object method = metadata.get("httpMethod");
            if (method != null) {
                return method.toString();
            }
        }
        return null;
    }

    /**
     * 이벤트에서 경로 추출
     *
     * AI Native v6.8: 실제 metadata 키에 맞게 수정
     * - "requestUri": ZeroTrustEventListener에서 설정됨
     * - "fullPath": HCADContextExtractor에서 설정됨
     * - "path": 설정되는 곳 없음 (제거)
     */
    private String extractPath(SecurityEvent event) {
        if (event.getMetadata() != null) {
            // ZeroTrustEventListener에서 설정
            Object uri = event.getMetadata().get("requestUri");
            if (uri != null) {
                return uri.toString();
            }
            // HCADContextExtractor에서 설정
            Object fullPath = event.getMetadata().get("fullPath");
            if (fullPath != null) {
                return fullPath.toString();
            }
        }
        return null;
    }

    /**
     * 위협 문서 저장
     *
     * Layer1ContextualStrategy.storeThreatDocument()와 동일한 로직입니다.
     *
     * AI Native v7.0: 순환 로직 방지
     * - RiskScore, Reasoning, Action 제거 - LLM 결과가 다음 분석에 영향을 미치면 안 됨
     * - 사실 데이터(User, IP, ThreatCategory)만 저장
     */
    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = buildBaseMetadata(event, decision, VectorDocumentType.THREAT.getValue());

            // 행동 패턴 추가
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatMetadata.put("behaviorPatterns", String.join(", ", decision.getBehaviorPatterns()));
            }

            // AI Native v7.0: 위협 설명 - 사실 데이터만 포함, LLM 결과(RiskScore, Reasoning, Action) 제거
            StringBuilder threatDesc = new StringBuilder("Contextual Threat:");

            if (event.getUserId() != null) {
                threatDesc.append(" User=").append(event.getUserId());
            }
            if (event.getSourceIp() != null) {
                threatDesc.append(", IP=").append(event.getSourceIp());
            }
            if (decision.getThreatCategory() != null) {
                threatDesc.append(", ThreatCategory=").append(decision.getThreatCategory());
            }
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatDesc.append(", BehaviorPatterns=").append(decision.getBehaviorPatterns());
            }
            // AI Native v7.0: action 제거 (LLM 결과 = 순환 로직)
            // 이전: threatDesc.append(", Action=").append(decision.getAction());
            // AI Native v7.0: RiskScore, Reasoning, Action 모두 제거 (순환 로직 방지)

            Document threatDoc = new Document(threatDesc.toString(), threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

            log.info("[SecurityDecisionPostProcessor] 위협 패턴 저장 완료: userId={}, threatCategory={}",
                event.getUserId(), decision.getThreatCategory());

        } catch (Exception e) {
            log.warn("[SecurityDecisionPostProcessor] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    /**
     * 벡터 저장용 공통 메타데이터 생성
     *
     * AbstractTieredStrategy.buildBaseMetadata()와 동일한 로직입니다.
     *
     * AI Native v7.0: 순환 로직 방지
     * - riskScore, confidence, action 제거 - LLM 결과가 다음 분석에 영향을 미치면 안 됨
     * - null인 경우 필드 생략 (LLM이 "unknown"을 실제 값으로 오해 방지)
     * - 사실 데이터(eventId, userId, sourceIp, sessionId)만 저장
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

        // AI Native v7.0: action, riskScore, confidence 모두 제거 (순환 로직 방지)
        // LLM 결과(action 포함)가 다음 분석에 영향을 미치면 독립적 분석 불가
        // action 저장 제거: 이전 BLOCK/ALLOW가 다음 판단에 편향을 줄 수 있음
        // threatCategory만 유지 (위협 유형 분류는 참조용으로 허용)
        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        // AI Native v6.8: 실제 metadata 키 사용 (requestUri)
        String requestUri = extractPath(event);
        if (requestUri != null) {
            metadata.put("requestUri", requestUri);
        }

        return metadata;
    }
}
