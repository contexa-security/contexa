package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Aspect
public class SandboxDecisionEnforcementAspect {

    private final SandboxDecisionEnforcementStore sandboxDecisionEnforcementStore;

    public SandboxDecisionEnforcementAspect(
            SandboxDecisionEnforcementStore sandboxDecisionEnforcementStore) {
        this.sandboxDecisionEnforcementStore = sandboxDecisionEnforcementStore;
    }

    @Around("execution(* io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler.handle(..)) && args(context)")
    public Object captureDecisionEnforcementCompletion(
            ProceedingJoinPoint proceedingJoinPoint,
            SecurityEventContext context) throws Throwable {

        Object proceeded = proceedingJoinPoint.proceed();
        capture(context, proceeded);
        return proceeded;
    }

    private void capture(SecurityEventContext context, Object proceeded) {
        if (context == null) {
            return;
        }

        SecurityEvent event = context.getSecurityEvent();
        if (event == null) {
            return;
        }

        String requestId = extractRequestId(event);
        if (requestId == null || requestId.isBlank()) {
            return;
        }

        ProcessingResult processingResult = context.getMetadata() != null
                ? (ProcessingResult) context.getMetadata().get("processingResult")
                : null;
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("eventId", event.getEventId());
        metadata.put("processingStatus", context.getProcessingStatus() != null
                ? context.getProcessingStatus().name()
                : null);
        if (processingResult != null) {
            metadata.put("processingAction", processingResult.getAction());
            metadata.put("proposedAction", processingResult.getProposedAction());
            metadata.put("confidence", processingResult.getConfidence());
            metadata.put("llmAuditConfidence", processingResult.getLlmAuditConfidence());
        }

        sandboxDecisionEnforcementStore.capture(new SandboxDecisionEnforcementSnapshot(
                requestId,
                event.getUserId(),
                processingResult != null ? processingResult.getAction() : null,
                proceeded instanceof Boolean decision ? decision : false,
                Instant.now(),
                immutableWithoutNulls(metadata)));
    }

    private String extractRequestId(SecurityEvent event) {
        if (event.getMetadata() == null) {
            return null;
        }
        Object requestId = event.getMetadata().get("requestId");
        if (requestId != null && !requestId.toString().isBlank()) {
            return requestId.toString();
        }
        Object correlationId = event.getMetadata().get("correlationId");
        return correlationId != null && !correlationId.toString().isBlank()
                ? correlationId.toString()
                : null;
    }

    private Map<String, Object> immutableWithoutNulls(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> sanitized = new LinkedHashMap<>();
        source.forEach((key, value) -> {
            if (key != null && value != null) {
                sanitized.put(key, value);
            }
        });
        return sanitized.isEmpty() ? Map.of() : Map.copyOf(sanitized);
    }
}
