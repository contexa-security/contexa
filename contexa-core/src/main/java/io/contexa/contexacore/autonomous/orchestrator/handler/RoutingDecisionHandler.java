package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.metrics.RoutingDecisionMetrics;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.tiered.routing.AdaptiveTierRouter;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 라우팅 결정 핸들러
 *
 * SecurityPlaneAgent의 라우팅 결정 로직을 분리
 * - AdaptiveTierRouter를 통한 처리 모드 결정
 * - 리스크 기반 라우팅
 * - AI Native: 모든 요청은 Cold Path(AI 분석)로 라우팅
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j

@RequiredArgsConstructor
public class RoutingDecisionHandler implements SecurityEventHandler {

    @Autowired(required = false)
    private AdaptiveTierRouter tierRouter;

    @Autowired(required = false)
    private RoutingDecisionMetrics routingMetrics;

    @Value("${security.plane.agent.similarity-threshold:0.70}")
    private double similarityThreshold;

    @Override
    public boolean handle(SecurityEventContext context) {
        log.info("[RoutingDecisionHandler] Processing event: {}", context.getSecurityEvent().getEventId());
        SecurityEvent event = context.getSecurityEvent();

        // 벡터 유사도 점수 가져오기 (VectorSimilarityHandler 에서 설정)
        Double similarityScore = (Double) context.getMetadata().get("similarityScore");

        if (similarityScore == null) {
            log.info("[RoutingDecisionHandler] No similarity score for routing decision: {}", event.getEventId());
            // 기본 라우팅 적용 (Zero Trust: 유사도가 없으면 위험으로 간주)
            applyDefaultRouting(context);
            return true;
        }

        log.info("[RoutingDecisionHandler] Making routing decision for event: {}", event.getEventId());

        // ===== 메트릭 수집: 라우팅 결정 시간 측정 시작 =====
        long startTime = System.nanoTime();

        try {
            // 벡터 유사도 기반 라우팅 결정
            ProcessingMode mode;
            double confidence = (Double) context.getMetadata().getOrDefault("vectorConfidence", 0.5);

            // AIAnalysisResult 에서 riskScore 가져오기 (이미 VectorSimilarityHandler 에서 계산됨)
            double riskScore;
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();
            if (aiResult != null) {
                riskScore = aiResult.getThreatLevel(); // 이미 계산된 값 재사용 (0.0 포함)
                log.debug("[RoutingDecisionHandler] Using AIAnalysisResult.threatLevel: {}", riskScore);
            } else {
                riskScore = 1.0 - similarityScore; // Fallback: 유사도의 역 = 위험도
                log.debug("[RoutingDecisionHandler] Calculated riskScore from similarityScore: {}", riskScore);
            }

            if (tierRouter != null) {
                mode = tierRouter.determineMode(riskScore, confidence, null);
                log.info("[RoutingDecisionHandler] Event {} routed to {} by AdaptiveTierRouter - similarity: {}, riskScore: {}, confidence: {}",
                    event.getEventId(), mode, String.format("%.3f", similarityScore),
                    String.format("%.3f", riskScore),
                    String.format("%.3f", confidence));
            } else {
                // 라우터가 없으면 유사도 기반 기본 로직 사용
                mode = determineModeFromSimilarity(similarityScore);
                log.info("[RoutingDecisionHandler] Event {} routed to {} by similarity logic - similarity: {}",
                    event.getEventId(), mode, String.format("%.3f", similarityScore));
            }

            // 라우팅 결정을 컨텍스트에 저장
            context.addMetadata("processingMode", mode);
            context.addMetadata("routingDecision", mode.toString());
            context.addMetadata("routingReason", getRoutingReasonBySimilarity(mode, similarityScore));
            context.addMetadata("routingTimestamp", System.currentTimeMillis());

            // 처리 모드별 추가 메타데이터
            addModeSpecificMetadata(context, mode, similarityScore, confidence);

            // ===== 메트릭 수집: 라우팅 결정 기록 =====
            long duration = System.nanoTime() - startTime;
            if (routingMetrics != null) {
                // AI Native: 모든 요청은 Cold Path
                routingMetrics.recordColdPath(duration, similarityScore, mode.toString());

                // EventRecorder 인터페이스를 통한 이벤트 기록
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("path_type", "cold");
                metadata.put("mode", mode.toString());
                metadata.put("similarity_score", similarityScore);
                metadata.put("risk_score", riskScore);
                metadata.put("confidence", confidence);
                metadata.put("duration", duration);
                metadata.put("event_id", event.getEventId());

                routingMetrics.recordEvent("routing_cold", metadata);
            }

            return true; // 다음 핸들러로 진행

        } catch (Exception e) {
            log.error("[RoutingDecisionHandler] Error making routing decision for event: {}", event.getEventId(), e);
            // 라우팅 오류 시 안전한 기본 모드 적용
            applyDefaultRouting(context);
            return true;
        }
    }

    private void applyDefaultRouting(SecurityEventContext context) {
        ProcessingMode defaultMode = ProcessingMode.AI_ANALYSIS;
        context.addMetadata("processingMode", defaultMode);
        context.addMetadata("routingDecision", defaultMode.toString());
        context.addMetadata("routingReason", "Zero Trust - no similarity score, treating as suspicious");
        context.addMetadata("similarityScore", 0.5);
        log.debug("[RoutingDecisionHandler] Applied default routing (Zero Trust): {}", defaultMode);
    }

    private ProcessingMode determineModeFromSimilarity(double similarityScore) {
        // AI Native: 모든 요청은 AI 분석을 통과 (Zero Trust)
        return ProcessingMode.AI_ANALYSIS;
    }

    private String getRoutingReasonBySimilarity(ProcessingMode mode, double similarityScore) {
        return switch (mode) {
            case AI_ANALYSIS -> String.format("AI Native analysis - similarity (%.2f)", similarityScore);
            case REALTIME_BLOCK -> String.format("High risk (%.2f) - realtime block", similarityScore);
            case SOAR_ORCHESTRATION -> String.format("Critical risk (%.2f) - SOAR orchestration required", similarityScore);
            case AWAIT_APPROVAL -> String.format("High-risk operation (%.2f) - awaiting approval", similarityScore);
        };
    }

    /**
     * 처리 모드별 추가 메타데이터 설정
     *
     * AI Native: 모든 요청은 Cold Path로 라우팅
     * isAnomaly는 이 시점에서 설정하지 않음 (AI 분석 후 결정)
     */
    private void addModeSpecificMetadata(SecurityEventContext context, ProcessingMode mode,
                                        double similarityScore, double confidence) {
        context.addMetadata("isRealtime", mode.isRealtime());
        context.addMetadata("isBlocking", mode.isBlocking());
        context.addMetadata("needsEscalation", mode.needsEscalation());
        context.addMetadata("needsMonitoring", mode.needsMonitoring());
        context.addMetadata("needsHumanIntervention", mode.needsHumanIntervention());

        // AI Native: 모든 요청은 Cold Path (AI 분석)
        context.addMetadata("requiresColdPath", true);
        context.addMetadata("similarityScore", similarityScore);
        log.info("[RoutingDecisionHandler] AI Native routing - similarity {}, routing to Cold Path",
            String.format("%.3f", similarityScore));

        // 즉시 처리 필요 표시
        if (mode.isRealtime() || mode.isBlocking()) {
            context.addMetadata("requiresImmediateAction", true);
        }

        // 에스컬레이션 필요 표시
        if (mode.needsEscalation()) {
            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
        }
    }

    @Override
    public String getName() {
        return "RoutingDecisionHandler";
    }

    @Override
    public int getOrder() {
        return 40; // LearningSystemHandler(30) 다음에 실행
    }

}