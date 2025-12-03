package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.metrics.RoutingDecisionMetrics;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;

/**
 * 라우팅 결정 핸들러
 *
 * AI Native 아키텍처:
 * - 모든 요청은 Cold Path(LLM 분석)로 직접 라우팅
 * - 유사도 기반 라우팅 완전 제거
 * - LLM이 riskScore, threatLevel, action을 직접 결정
 * - 플랫폼은 컨텍스트 수집과 LLM 호출만 담당
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j

@RequiredArgsConstructor
public class RoutingDecisionHandler implements SecurityEventHandler {

    @Autowired(required = false)
    private RoutingDecisionMetrics routingMetrics;

    // AI Native: similarityThreshold 제거 - 유사도 기반 판단 사용 안 함

    /**
     * AI Native: 모든 요청을 Cold Path(LLM 분석)로 직접 라우팅
     *
     * AI Native 원칙:
     * - 모든 판단은 LLM이 Cold Path에서 수행
     * - 플랫폼은 컨텍스트 수집과 라우팅만 담당
     */
    @Override
    public boolean handle(SecurityEventContext context) {
        log.info("[RoutingDecisionHandler][AI Native] Processing event: {}", context.getSecurityEvent().getEventId());
        SecurityEvent event = context.getSecurityEvent();

        long startTime = System.nanoTime();

        try {
            // AI Native: 모든 요청은 AI_ANALYSIS (Cold Path)로 직접 라우팅
            ProcessingMode mode = ProcessingMode.AI_ANALYSIS;

            // 라우팅 결정을 컨텍스트에 저장
            context.addMetadata("processingMode", mode);
            context.addMetadata("routingDecision", mode.toString());
            context.addMetadata("routingReason", "AI Native - all requests routed to LLM analysis");
            context.addMetadata("routingTimestamp", System.currentTimeMillis());
            context.addMetadata("requiresColdPath", true);

            // 처리 모드 메타데이터
            context.addMetadata("isRealtime", mode.isRealtime());
            context.addMetadata("isBlocking", mode.isBlocking());
            context.addMetadata("needsEscalation", mode.needsEscalation());
            context.addMetadata("needsMonitoring", mode.needsMonitoring());
            context.addMetadata("needsHumanIntervention", mode.needsHumanIntervention());

            log.info("[RoutingDecisionHandler][AI Native] Event {} routed to Cold Path (LLM analysis)",
                event.getEventId());

            // 메트릭 수집
            long duration = System.nanoTime() - startTime;
            if (routingMetrics != null) {
                routingMetrics.recordColdPath(duration, mode.toString());

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("path_type", "cold");
                metadata.put("mode", mode.toString());
                metadata.put("duration", duration);
                metadata.put("event_id", event.getEventId());
                routingMetrics.recordEvent("routing_cold", metadata);
            }

            return true;

        } catch (Exception e) {
            log.error("[RoutingDecisionHandler][AI Native] Error routing event: {}", event.getEventId(), e);
            // 오류 시에도 Cold Path로 라우팅
            context.addMetadata("processingMode", ProcessingMode.AI_ANALYSIS);
            context.addMetadata("routingDecision", ProcessingMode.AI_ANALYSIS.toString());
            context.addMetadata("routingReason", "AI Native - error fallback to LLM analysis");
            context.addMetadata("requiresColdPath", true);
            return true;
        }
    }

    // AI Native: 유사도 기반 라우팅 메서드 제거
    // - applyDefaultRouting() 제거
    // - determineModeFromSimilarity() 제거
    // - getRoutingReasonBySimilarity() 제거
    // - addModeSpecificMetadata() 제거
    // 모든 요청은 handle()에서 직접 Cold Path로 라우팅

    @Override
    public String getName() {
        return "RoutingDecisionHandler";
    }

    @Override
    public int getOrder() {
        return 40; // LearningSystemHandler(30) 다음에 실행
    }

}