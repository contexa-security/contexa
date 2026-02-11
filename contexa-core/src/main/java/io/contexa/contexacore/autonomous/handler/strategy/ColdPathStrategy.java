package io.contexa.contexacore.autonomous.handler.strategy;

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
        try {
            return coldPathProcessor.processEvent(context.getSecurityEvent(), 0.0);
        } catch (Exception e) {
            log.error("[ColdPathStrategy] Error processing event: {}", context.getSecurityEvent().getEventId(), e);
            return ProcessingResult.builder()
                .success(false)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .message("AI analysis processing failed")
                .riskScore(0.0)
                .build();
        }
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
