package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import java.util.HashMap;
import java.util.Map;

/**
 * Threat Score 업데이트 핸들러
 *
 * ThreatScoreOrchestrator를 통한 중앙집중식 Threat Score 관리
 * - AI Native: LLM riskScore를 직접 설정
 * - ThreatScoreOrchestrator를 통한 원자적 업데이트
 * - 모든 요청은 setThreatScore() 사용 (AI Native)
 *
 * @author contexa
 * @since 1.0
 */

@RequiredArgsConstructor
public class ThreatScoreHandler implements SecurityEventHandler {

    private static final Logger log = LoggerFactory.getLogger(ThreatScoreHandler.class);

    @Autowired(required = false)
    private ThreatScoreOrchestrator threatScoreOrchestrator;

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();

        // 기본 검증
        if (threatScoreOrchestrator == null) {
            log.warn("[ThreatScoreHandler] ThreatScoreOrchestrator not available, skipping threat score update");
            return true;
        }

        if (event.getUserId() == null) {
            log.warn("[ThreatScoreHandler] No userId in event, skipping threat score update");
            return true;
        }

        // 1. ProcessingResult 추출
        ProcessingResult processingResult = (ProcessingResult) context.getMetadata().get("processingResult");
        if (processingResult == null) {
            log.warn("[ThreatScoreHandler] No ProcessingResult found for event {}, skipping", event.getEventId());
            context.addMetadata("threatScoreUpdated", false);
            return true;
        }

        // 2. AI Native: riskScore 추출 (LLM 분석 결과)
        double riskScore = processingResult.getRiskScore();

        // riskScore가 0이고 AI 분석이 수행되지 않은 경우 스킵
        if (riskScore == 0.0 && !processingResult.isAiAnalysisPerformed()) {
            log.debug("[ThreatScoreHandler] No riskScore available - userId: {}", event.getUserId());
            context.addMetadata("threatScoreUpdated", false);
            return true;
        }

        // 3. AI Native: LLM riskScore 직접 설정
        try {
            String reason = determineUpdateReason(processingResult);
            Map<String, Object> metadata = prepareMetadata(context, processingResult);

            // AI Native: ThreatScoreOrchestrator.setThreatScore() 사용 (직접 설정)
            double newThreatScore = threatScoreOrchestrator.setThreatScore(
                event.getUserId(),
                riskScore,
                reason,
                metadata
            );

            log.info("[ThreatScoreHandler][AI Native] Threat Score set - userId: {}, riskScore: {}, savedScore: {}, path: {}",
                event.getUserId(),
                String.format("%.3f", riskScore),
                String.format("%.3f", newThreatScore),
                processingResult.getProcessingPath());

            // 4. 컨텍스트에 결과 저장
            context.addMetadata("threatScoreUpdated", true);
            context.addMetadata("newThreatScore", newThreatScore);
            context.addMetadata("riskScore", riskScore);
            context.addMetadata("aiNative", true);
            context.addMetadata("threatScoreReason", reason);

        } catch (Exception e) {
            log.error("[ThreatScoreHandler] Failed to set Threat Score for event: {}", event.getEventId(), e);
            context.addMetadata("threatScoreUpdateError", e.getMessage());
        }

        return true; // 다음 핸들러로 계속 진행
    }


    /**
     * Threat Score 업데이트 이유 결정
     *
     * AI Native 원칙:
     * - LLM 분석 결과(analysisData)에서 reason/threatLevel 직접 사용
     * - 임계값 기반 분류 제거
     * - LLM의 판단을 그대로 반영
     */
    private String determineUpdateReason(ProcessingResult result) {
        String pathPrefix = "[AI]";

        // AI Native: analysisData에서 LLM의 분석 결과 직접 사용
        if (result.getAnalysisData() != null) {
            Object reason = result.getAnalysisData().get("reason");
            Object threatLevel = result.getAnalysisData().get("threatLevel");
            Object action = result.getAnalysisData().get("action");

            if (reason != null && !reason.toString().isEmpty()) {
                return pathPrefix + reason.toString().toUpperCase().replace(" ", "_");
            }
            if (threatLevel != null) {
                return pathPrefix + threatLevel.toString() + "_THREAT";
            }
            if (action != null) {
                return pathPrefix + action.toString() + "_ACTION";
            }
        }

        // Fallback: incidentSeverity 기반 (LLM이 설정한 경우)
        if (result.getIncidentSeverity() != null) {
            return pathPrefix + result.getIncidentSeverity() + "_INCIDENT";
        }

        // 기본값: AI 분석 완료
        return pathPrefix + "AI_ANALYSIS_COMPLETE";
    }

    /**
     * Threat Score 업데이트 메타데이터 준비
     * ProcessingResult 기반으로 처리 경로 정보 포함
     */
    private Map<String, Object> prepareMetadata(SecurityEventContext context, ProcessingResult result) {
        Map<String, Object> metadata = new HashMap<>();

        // 기본 정보
        metadata.put("eventId", context.getSecurityEvent().getEventId());
        metadata.put("eventType", context.getSecurityEvent().getEventType().toString());

        // ProcessingResult 정보
        if (result.getProcessingPath() != null) {
            metadata.put("processingPath", result.getProcessingPath().toString());
        }
        metadata.put("riskLevel", result.getCurrentRiskLevel());
        metadata.put("processingTimeMs", result.getProcessingTimeMs());
        metadata.put("aiAnalysisPerformed", result.isAiAnalysisPerformed());

        // aiAnalysisLevel은 int 이므로 > 0 체크
        if (result.getAiAnalysisLevel() > 0) {
            metadata.put("aiAnalysisLevel", result.getAiAnalysisLevel());
        }

        // AI 분석 정보 (있을 경우)
        if (context.getAiAnalysisResult() != null) {
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();
            metadata.put("confidenceScore", aiResult.getConfidenceScore());
            metadata.put("aiModel", aiResult.getAiModel());
        }

        // 위협 평가 정보 (있을 경우)
        if (context.getMetadata().get("threatAssessmentId") != null) {
            metadata.put("threatAssessmentId", context.getMetadata().get("threatAssessmentId"));
        }

        return metadata;
    }

    // 세션 위협 및 이상 탐지 관련 메서드들 제거됨
    // 이러한 기능들은 SessionInvalidationHandler의 역할임

    @Override
    public String getName() {
        return "ThreatScoreHandler";
    }

    @Override
    public int getOrder() {
        return 55; // ProcessingExecutionHandler(50) 이후, MetricsHandler(60) 이전
    }
}