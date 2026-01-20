package io.contexa.contexacore.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@RequiredArgsConstructor
public class ColdPathStrategy implements ProcessingStrategy {

    private final ColdPathEventProcessor coldPathProcessor;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.info("[ColdPathStrategy] Processing AI analysis for event: {}", event.getEventId());

        try {
            
            double riskScore = extractRiskScore(context);

            
            ProcessingResult result = coldPathProcessor.processEvent(event, riskScore);

            
            
            context.addMetadata("aiAnalysisComplete", true);
            context.addMetadata("coldPathResult", result.isSuccess());
            context.addMetadata("riskScore", result.getRiskScore());

            log.info("[ColdPathStrategy] AI analysis completed for event {} - success: {}, riskScore: {}",
                event.getEventId(), result.isSuccess(), result.getRiskScore());

            
            return ProcessingResult.builder()
                .success(result.isSuccess())
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .riskScore(result.getRiskScore())  
                .currentRiskLevel(result.getCurrentRiskLevel())
                .executedActions(result.getExecutedActions())
                .metadata(result.getMetadata())
                .message(result.getMessage())
                .requiresIncident(result.isRequiresIncident())
                .incidentSeverity(parseIncidentSeverity(result.getIncidentSeverity()))
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
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .message("AI analysis processing failed")
                .riskScore(0.0)  
                .build();
        }
    }

    
    private ProcessingResult.IncidentSeverity parseIncidentSeverity(String severity) {
        if (severity == null || severity.isBlank()) {
            return null;
        }
        try {
            return ProcessingResult.IncidentSeverity.valueOf(severity);
        } catch (IllegalArgumentException e) {
            log.warn("[ColdPathStrategy] Invalid incident severity: {}", severity);
            return null;
        }
    }

    
    private double extractRiskScore(SecurityEventContext context) {
        if (context.getAiAnalysisResult() == null) {
            
            log.debug("[ColdPathStrategy][AI Native] No AI analysis result, riskScore=-1.0");
            return -1.0;
        }

        
        
        double threatLevel = context.getAiAnalysisResult().getThreatLevel();
        log.debug("[ColdPathStrategy][AI Native] Extracted riskScore from threatLevel: {}", threatLevel);
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