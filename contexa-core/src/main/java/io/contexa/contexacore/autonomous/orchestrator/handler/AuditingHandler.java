package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 감사 로깅 핸들러 - AI Native
 *
 * SecurityPlaneAgent의 감사 로깅 로직을 분리
 * - 보안 이벤트 감사
 * - 위협 평가 감사
 * - 처리 결정 감사
 * - 성능 메트릭 감사
 *
 * AI Native 원칙:
 * - LLM이 결정한 ThreatLevel을 그대로 기록
 * - 임계값 기반 ThreatLevel 매핑 제거
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j

@RequiredArgsConstructor
public class AuditingHandler implements SecurityEventHandler {

    @Autowired(required = false)
    private SecurityPlaneAuditLogger auditLogger;

    @Override
    public boolean handle(SecurityEventContext context) {
        if (auditLogger == null) {
            log.debug("[AuditingHandler] Audit logger not available, skipping audit");
            return true; // 감사 로깅은 선택적이므로 계속 진행
        }

        SecurityEvent event = context.getSecurityEvent();
        log.debug("[AuditingHandler] Recording audit logs for event: {}", event.getEventId());

        try {
            // 1. 보안 이벤트 감사
            auditSecurityEvent(context);

            // 2. 위협 평가 감사
            auditThreatAssessment(context);

            // 3. 처리 결정 감사
            auditProcessingDecision(context);

            // 4. 성능 메트릭 감사 (나중에 ProcessingExecutionHandler 완료 후)
            // 여기서는 스킵하고 최종 처리 후에 기록

            context.addMetadata("auditRecorded", true);
            context.addMetadata("auditTimestamp", System.currentTimeMillis());

            log.debug("[AuditingHandler] Audit logs recorded for event: {}", event.getEventId());
            return true; // 다음 핸들러로 진행

        } catch (Exception e) {
            log.error("[AuditingHandler] Error recording audit logs for event: {}", event.getEventId(), e);
            // 감사 로깅 오류는 처리를 중단하지 않음
            context.addMetadata("auditError", e.getMessage());
            return true;
        }
    }

    /**
     * 보안 이벤트 감사 기록
     */
    private void auditSecurityEvent(SecurityEventContext context) {
        try {
            SecurityEvent event = context.getSecurityEvent();
            String agentId = (String) context.getMetadata().get("agentId");
            if (agentId == null) {
                agentId = "security-plane-agent";
            }

            String auditContext = String.format("Processing by %s - Status: %s",
                getName(), context.getProcessingStatus());

            auditLogger.auditSecurityEvent(event, agentId, auditContext);

        } catch (Exception e) {
            log.error("[AuditingHandler] Failed to audit security event", e);
        }
    }

    /**
     * 위협 평가 감사 기록 - AI Native
     */
    private void auditThreatAssessment(SecurityEventContext context) {
        try {
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();
            if (aiResult == null) {
                return;
            }

            SecurityEvent event = context.getSecurityEvent();

            // AI Native: threatLevel은 LLM이 결정해야 함
            // 현재 AIAnalysisResult에는 ThreatLevel 필드가 없으므로 INFO 사용
            // 향후 AIAnalysisResult에 LLM이 직접 결정한 ThreatLevel 필드 추가 필요
            ThreatAssessment.ThreatLevel threatLevel = ThreatAssessment.ThreatLevel.INFO;

            // ThreatAssessment 재구성
            ThreatAssessment assessment = ThreatAssessment.builder()
                .assessmentId((String) context.getMetadata().get("threatAssessmentId"))
                .riskScore(aiResult.getThreatLevel())
                .confidence(aiResult.getConfidenceScore())
                .reason(aiResult.getSummary())
                .evaluator(aiResult.getAiModel())
                .threatLevel(threatLevel)  // AI Native: LLM이 결정해야 함 (현재 기본값)
                .assessedAt(LocalDateTime.now())
                .build();

            String evaluator = (String) context.getMetadata().get("evaluator");
            if (evaluator == null) {
                evaluator = aiResult.getAiModel();
            }

            String strategy = "IntegratedThreatEvaluator";
            if (Boolean.FALSE.equals(context.getMetadata().get("consensusAchieved"))) {
                strategy = "DynamicStrategySelector";
            }

            long processingTime = aiResult.getAnalysisTimeMs();

            auditLogger.auditThreatAssessment(event, assessment, evaluator, strategy, processingTime);

        } catch (Exception e) {
            log.error("[AuditingHandler][AI Native] Failed to audit threat assessment", e);
        }
    }

    /**
     * 처리 결정 감사 기록
     */
    private void auditProcessingDecision(SecurityEventContext context) {
        try {
            ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");
            if (mode == null) {
                return;
            }

            SecurityEvent event = context.getSecurityEvent();
            String router = "RoutingDecisionHandler";
            String reason = (String) context.getMetadata().get("routingReason");

            Map<String, Object> decisionContext = Map.of(
                "riskScore", context.getAiAnalysisResult() != null ?
                    context.getAiAnalysisResult().getThreatLevel() : 0.0,
                "confidence", context.getAiAnalysisResult() != null ?
                    context.getAiAnalysisResult().getConfidenceScore() : 0.0,
                "processingMode", mode.toString(),
                "timestamp", System.currentTimeMillis()
            );

            auditLogger.auditProcessingDecision(event, mode, router, reason, decisionContext);

        } catch (Exception e) {
            log.error("[AuditingHandler] Failed to audit processing decision", e);
        }
    }

    // AI Native: 임계값 기반 ThreatLevel 매핑 제거
    // LLM이 ThreatLevel을 직접 결정해야 함
    // private ThreatAssessment.ThreatLevel mapThreatLevel(double riskScore) { ... }

    @Override
    public String getName() {
        return "AuditingHandler";
    }

    @Override
    public int getOrder() {
        return 45; // RoutingDecisionHandler(40) 다음, ProcessingExecutionHandler(50) 이전에 실행
    }
}