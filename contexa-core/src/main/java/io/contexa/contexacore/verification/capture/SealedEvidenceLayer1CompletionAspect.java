package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import java.util.Objects;
import java.util.function.Consumer;
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
public class SealedEvidenceLayer1CompletionAspect {

    private final Consumer<SecurityEvent> traceCompleter;

    public SealedEvidenceLayer1CompletionAspect(SealedEvidencePromptTraceStore traceStore) {
        this(Objects.requireNonNull(traceStore, "traceStore must not be null")::complete);
    }

    public SealedEvidenceLayer1CompletionAspect(Consumer<SecurityEvent> traceCompleter) {
        this.traceCompleter = Objects.requireNonNull(traceCompleter, "traceCompleter must not be null");
    }

    @AfterReturning(
            pointcut = "execution(* io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy.evaluate(..)) && args(event)")
    public void completeAfterLayer1(SecurityEvent event) {
        if (event == null) {
            return;
        }
        try {
            traceCompleter.accept(event);
        } catch (Exception e) {
            log.error("[SealedEvidence] Failed to complete prompt trace after Layer1: eventId={}",
                    event.getEventId(), e);
        }
    }
}
