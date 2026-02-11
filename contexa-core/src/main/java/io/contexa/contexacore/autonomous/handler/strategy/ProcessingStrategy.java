package io.contexa.contexacore.autonomous.handler.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;

public interface ProcessingStrategy {

    ProcessingResult process(SecurityEventContext context);

    ProcessingMode getSupportedMode();

    default boolean supports(ProcessingMode mode) {
        return mode == getSupportedMode();
    }

    default boolean canProcess(SecurityEventContext context) {
        ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");
        return mode != null && supports(mode);
    }

    default String getName() {
        return getSupportedMode().toString() + "Strategy";
    }
}