package io.contexa.contexacore.verification.capture;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;

/**
 * Enterprise AOP aspect that captures PromptGenerationResult at the exact moment
 * PromptGenerator.generatePrompt() completes, along with the full SecurityDecisionContext.
 *
 * This is the production-grade equivalent of the TDD's OfficialVerificationPromptTraceTestConfiguration
 * which overrides PromptGenerator via @Primary. Instead of subclassing, this aspect observes
 * the original PromptGenerator without modifying it.
 *
 * Capture occurs only for security decision requests (SecurityDecisionContext).
 * Non-security requests are ignored.
 */
@Aspect
@Slf4j
@RequiredArgsConstructor
public class SealedEvidencePromptCaptureAspect {

    private final SealedEvidencePromptTraceStore traceStore;

    @AfterReturning(
            pointcut = "execution(* io.contexa.contexacore.std.components.prompt.PromptGenerator.generatePrompt(..)) && args(request, contextInfo, systemMetadata)",
            returning = "result", argNames = "request,contextInfo,systemMetadata,result")
    public void capturePromptGenerationResult(
            AIRequest<? extends DomainContext> request,
            String contextInfo,
            String systemMetadata,
            PromptGenerationResult result) {

        if (result == null || request == null) {
            return;
        }

        if (!(request.getContext() instanceof SecurityDecisionContext securityDecisionContext)) {
            return;
        }

        try {
            traceStore.capture(new SecurityDecisionCaptureContextAdapter(securityDecisionContext, result));
        } catch (Exception e) {
            log.error("[SealedEvidence] Failed to capture prompt trace", e);
        }
    }
}
