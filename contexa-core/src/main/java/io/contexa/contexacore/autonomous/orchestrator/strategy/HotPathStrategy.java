package io.contexa.contexacore.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.HotPathEventProcessor;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Pass-Through 처리 전략
 *
 * 낮은 위험 이벤트를 Hot Path로 빠르게 처리
 * AI 분석 없이 즉시 통과
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HotPathStrategy implements ProcessingStrategy {

    @Autowired(required = false)
    private HotPathEventProcessor hotPathProcessor;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.error("[PassThroughStrategy] Processing low-risk event: {}", event.getEventId());

        if (hotPathProcessor == null) {
            log.error("[PassThroughStrategy] HotPathProcessor not available");
            return ProcessingResult.builder()
                .success(false)
                .processingPath("PASS_THROUGH")
                .message("HotPathProcessor not available")
                .build();
        }

        try {
            double riskScore = context.getAiAnalysisResult() != null ?
                context.getAiAnalysisResult().getThreatLevel() : 0.0;

            // Hot Path 처리
            ProcessingResult result = hotPathProcessor.processEvent(event, riskScore);

            // 컨텍스트 업데이트
            context.addResponseAction("PASS_THROUGH", "Event processed via Hot Path");
            context.addMetadata("hotPathResult", result);

            log.error("[PassThroughStrategy] Event {} processed via Hot Path - success: {}",
                event.getEventId(), result.isSuccess());

            return result;

        } catch (Exception e) {
            log.error("[PassThroughStrategy] Error processing event: {}", event.getEventId(), e);
            return ProcessingResult.builder()
                .success(false)
                .processingPath("PASS_THROUGH")
                .message("Processing error: " + e.getMessage())
                .build();
        }
    }

    @Override
    public ProcessingMode getSupportedMode() {
        return ProcessingMode.PASS_THROUGH;
    }
}