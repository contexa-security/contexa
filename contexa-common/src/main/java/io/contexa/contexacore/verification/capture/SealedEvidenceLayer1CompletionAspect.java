package io.contexa.contexacore.verification.capture;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;

/**
 * Enterprise AOP aspect that marks a prompt trace snapshot as completed
 * after Layer1ContextualStrategy.evaluate() finishes.
 *
 * This ensures the snapshot includes the final event state after
 * post-processing, vector storage, and baseline learning have completed.
 *
 * Production-grade equivalent of TDD's OfficialVerificationLayer1CompletionAspect.
 */
@Aspect
@Slf4j
@RequiredArgsConstructor
public class SealedEvidenceLayer1CompletionAspect {

    private final SealedEvidencePromptTraceStore traceStore;

    @AfterReturning(
            pointcut = "execution(* io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy.evaluate(..)) && args(event)")
    public void completeAfterLayer1(SecurityEvent event) {
        if (event == null) {
            return;
        }
        try {
            traceStore.complete(event);
        } catch (Exception e) {
            log.error("[SealedEvidence] Failed to complete prompt trace after Layer1: eventId={}",
                    event.getEventId(), e);
        }
    }
}
