package io.contexa.contexacore.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * AI 기반 상세 분석 전략
 *
 * ColdPathEventProcessor를 통한 AI 기반 상세 분석 수행
 * 모든 AI_ANALYSIS 모드 이벤트를 통합 처리
 *
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ColdPathStrategy implements ProcessingStrategy {

    @Autowired(required = false)
    private ColdPathEventProcessor coldPathProcessor;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.info("[ColdPathStrategy] Processing AI analysis for event: {}", event.getEventId());

        if (coldPathProcessor == null) {
            log.error("[ColdPathStrategy] ColdPathProcessor not available");
            return ProcessingResult.builder()
                .success(false)
                .processingPath("AI_ANALYSIS")
                .message("ColdPathProcessor not available")
                .build();
        }

        try {
            // AI 분석 결과에서 위험도 점수 추출 (0.0-1.0 스케일)
            double riskScore = extractRiskScore(context);

            // ColdPathProcessor를 통한 AI 분석 실행
            ProcessingResult result = coldPathProcessor.processEvent(event, riskScore);

            // Context에 분석 완료 메타데이터 추가
            context.addMetadata("aiAnalysisComplete", true);
            context.addMetadata("coldPathResult", result.isSuccess());
            context.addMetadata("threatScoreAdjustment", result.getThreatScoreAdjustment());

            log.info("[ColdPathStrategy] AI analysis completed for event {} - success: {}, threatAdjustment: {}",
                event.getEventId(), result.isSuccess(), result.getThreatScoreAdjustment());

            // CRITICAL FIX: threatScoreAdjustment를 포함한 완전한 결과 반환
            return ProcessingResult.builder()
                .success(result.isSuccess())
                .processingPath("AI_ANALYSIS")
                .threatScoreAdjustment(result.getThreatScoreAdjustment())  // 추가됨
                .currentRiskLevel(result.getCurrentRiskLevel())
                .executedActions(result.getExecutedActions())
                .metadata(result.getMetadata())
                .message(result.getMessage())
                .requiresIncident(result.isRequiresIncident())
                .incidentSeverity(result.getIncidentSeverity() != null ?
                    ProcessingResult.IncidentSeverity.valueOf(result.getIncidentSeverity()) : null)
                .threatIndicators(result.getThreatIndicators())
                .recommendedActions(result.getRecommendedActions())
                .aiAnalysisPerformed(result.isAiAnalysisPerformed())
                .aiAnalysisLevel(result.getAiAnalysisLevel())
                .analysisData(result.getAnalysisData())
                .processingTimeMs(result.getProcessingTimeMs())
                .processedAt(result.getProcessedAt())
                .status(result.getStatus())
                .build();

        } catch (Exception e) {
            log.error("[ColdPathStrategy] Error processing event: {}", event.getEventId(), e);
            return ProcessingResult.builder()
                .success(false)
                .processingPath("AI_ANALYSIS")
                .message("Processing error: " + e.getMessage())
                .threatScoreAdjustment(0.0)  // 실패 시 조정 없음
                .build();
        }
    }

    /**
     * Context에서 위험도 점수 추출 (0.0-1.0 스케일)
     *
     * @param context 보안 이벤트 컨텍스트
     * @return 위험도 점수 (기본값: 0.7)
     */
    private double extractRiskScore(SecurityEventContext context) {
        if (context.getAiAnalysisResult() == null) {
            log.debug("[ColdPathStrategy] No AI analysis result, using default riskScore: 0.5");
            return 0.5;  // Zero Trust 중립값
        }

        // threatLevel 필드를 riskScore로 사용 (0.0-1.0 범위)
        // 0.0(완전 안전)도 유효한 값이므로 > 0 조건 제거
        double threatLevel = context.getAiAnalysisResult().getThreatLevel();
        log.debug("[ColdPathStrategy] Extracted riskScore from threatLevel: {}", threatLevel);
        return threatLevel;
    }

    @Override
    public ProcessingMode getSupportedMode() {
        return ProcessingMode.AI_ANALYSIS;
    }

    @Override
    public boolean supports(ProcessingMode mode) {
        return mode == ProcessingMode.AI_ANALYSIS;
    }
}