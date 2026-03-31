package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;

/**
 * Test-only aspect that marks a prompt trace as completed only after
 * Layer1ContextualStrategy.evaluate has fully finished.
 *
 * This keeps the replay test aligned with the real async boundary:
 * prompt capture happens in the middle, but the round is not considered
 * complete until Layer1 post-processing and vector storage are done.
 */
@Aspect
public class SandboxLayer1CompletionAspect {

    private final SandboxPromptTraceStore sandboxPromptTraceStore;

    public SandboxLayer1CompletionAspect(SandboxPromptTraceStore sandboxPromptTraceStore) {
        this.sandboxPromptTraceStore = sandboxPromptTraceStore;
    }

    @AfterReturning(
            pointcut = "execution(* io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy.evaluate(..)) && args(event)")
    public void completeAfterLayer1(SecurityEvent event) {
        if (event != null) {
            sandboxPromptTraceStore.complete(event);
        }
    }
}
