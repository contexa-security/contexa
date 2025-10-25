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
 * - 위험도에 따른 Threat Score 조정
 * - ThreatScoreOrchestrator를 통한 원자적 업데이트
 * - Threat Score로 통일된 처리
 *
 * @author contexa
 * @since 1.0
 */
@Component
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

        // 2. adjustment 추출 및 검증
        Double adjustment = processingResult.getThreatScoreAdjustment();
        if (Math.abs(adjustment) < 0.001) {
            log.debug("[ThreatScoreHandler] No adjustment needed - userId: {}, adjustment: {}",
                event.getUserId(), adjustment);
            context.addMetadata("threatScoreUpdated", false);
            return true;
        }

        // 3. Threat Score 업데이트 (핵심 기능)
        try {
            String reason = determineUpdateReason(processingResult);
            Map<String, Object> metadata = prepareMetadata(context, processingResult);

            // ThreatScoreOrchestrator를 통한 업데이트
            double newThreatScore = threatScoreOrchestrator.updateThreatScore(
                event.getUserId(),
                adjustment,
                reason,
                metadata
            );

            log.info("[ThreatScoreHandler] Threat Score updated - userId: {}, adjustment: {}, newScore: {}, path: {}",
                event.getUserId(),
                String.format("%.3f", adjustment),
                String.format("%.3f", newThreatScore),
                processingResult.getProcessingPath());

            // 4. 컨텍스트에 결과 저장
            context.addMetadata("threatScoreUpdated", true);
            context.addMetadata("newThreatScore", newThreatScore);
            context.addMetadata("threatScoreAdjustment", adjustment);
            context.addMetadata("threatScoreReason", reason);

        } catch (Exception e) {
            log.error("[ThreatScoreHandler] Failed to update Threat Score for event: {}", event.getEventId(), e);
            context.addMetadata("threatScoreUpdateError", e.getMessage());
        }

        return true; // 다음 핸들러로 계속 진행
    }


    /**
     * Threat Score 업데이트 이유 결정
     * ProcessingResult 기반으로 경로와 위험도를 반영
     */
    private String determineUpdateReason(ProcessingResult result) {
        double riskLevel = result.getCurrentRiskLevel();
        Object pathObj = result.getProcessingPath();

        // ProcessingPath 미자열 추출
        String pathPrefix;
        if (pathObj instanceof ProcessingResult.ProcessingPath) {
            ProcessingResult.ProcessingPath path = (ProcessingResult.ProcessingPath) pathObj;
            pathPrefix = path == ProcessingResult.ProcessingPath.HOT_PATH ? "[HOT]" : "[COLD]";
        } else if (pathObj != null) {
            String pathStr = pathObj.toString().toUpperCase();
            pathPrefix = pathStr.contains("HOT") ? "[HOT]" : "[COLD]";
        } else {
            pathPrefix = "[UNKNOWN]";
        }

        if (riskLevel >= 0.9) {
            return pathPrefix + "CRITICAL_THREAT_DETECTED";
        } else if (riskLevel >= 0.7) {
            return pathPrefix + "HIGH_RISK_ACTIVITY";
        } else if (riskLevel < 0.3) {
            return pathPrefix + "NORMAL_ACTIVITY";
        } else {
            return pathPrefix + "MODERATE_RISK";
        }
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