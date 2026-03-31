package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Aspect
public class SandboxPromptHarvestLayer2ShortCircuitAspect {

    @Around("execution(* io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy.evaluate(..)) && args(event)")
    public Object shortCircuitLayer2DuringPromptHarvest(
            ProceedingJoinPoint proceedingJoinPoint,
            SecurityEvent event) throws Throwable {

        if (!SandboxDecisionBenchmarkSettings.useRealLlm()
                || !SandboxDecisionBenchmarkExecutionMode.isPromptHarvest()) {
            return proceedingJoinPoint.proceed();
        }

        return synthesizeAssessment(event);
    }

    private ThreatAssessment synthesizeAssessment(SecurityEvent event) {
        Map<String, Object> metadata = event != null && event.getMetadata() != null
                ? event.getMetadata()
                : Map.of();
        String anomalySignal = text(metadata.get("anomalySignal"));
        boolean criticalPath = contains(text(metadata.get("requestPath")), "/critical/");
        boolean sparseEvidence = contains(anomalySignal, "SPARSE")
                || contains(anomalySignal, "PARTIAL")
                || contains(anomalySignal, "APPROVAL_AMBIGUITY");
        String action = (criticalPath || sparseEvidence)
                ? ZeroTrustAction.ESCALATE.name()
                : ZeroTrustAction.CHALLENGE.name();
        double confidence = sparseEvidence ? 0.62d : 0.68d;
        String reasoning = sparseEvidence
                ? "Prompt harvest mode bypassed Layer2 replay and preserved uncertainty for later real decision evaluation."
                : "Prompt harvest mode bypassed Layer2 replay and preserved escalation context for later real decision evaluation.";

        return ThreatAssessment.builder()
                .eventId(event != null ? event.getEventId() : null)
                .riskScore(null)
                .llmAuditRiskScore(null)
                .assessedAt(LocalDateTime.now())
                .indicators(List.of("PROMPT_HARVEST_LAYER2_SHORT_CIRCUIT"))
                .recommendedActions(new ArrayList<>(List.of("DEFER_TO_REAL_DECISION_REPLAY")))
                .strategyName("Layer2-PromptHarvest-ShortCircuit")
                .confidence(confidence)
                .llmAuditConfidence(confidence)
                .action(action)
                .autonomousAction(action)
                .reasoning(reasoning)
                .autonomyConstraintApplied(false)
                .autonomyConstraintReasons(List.of())
                .autonomyConstraintSummary("Prompt harvest keeps Layer2 outputs lightweight and defers final judgment to real decision replay.")
                .shouldEscalate(false)
                .build();
    }

    private boolean contains(String left, String right) {
        return left != null
                && right != null
                && left.toLowerCase(Locale.ROOT).contains(right.toLowerCase(Locale.ROOT));
    }

    private String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
