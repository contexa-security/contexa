package io.contexa.contexacore.verification.capture;

import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of prompt generation inputs and outputs,
 * captured at the exact moment of PromptGenerator.generatePrompt() completion.
 *
 * This record carries everything needed to reassemble or verify a prompt:
 * - The SecurityEvent that triggered the decision
 * - Session and behavior analysis at decision time
 * - RAG documents retrieved and authorized
 * - Raw and LLM-view prompts (before and after compression)
 * - Prompt metadata and execution metadata
 *
 * Modeled after TDD source: OfficialVerificationPromptTraceSnapshot
 */
public record SealedEvidencePromptSnapshot(
        String requestId,
        Instant capturedAt,
        SecurityEvent securityEvent,
        Object sessionContext,
        Object behaviorAnalysis,
        List<Document> relatedDocuments,
        String rawSystemPrompt,
        String rawUserPrompt,
        String systemPrompt,
        String userPrompt,
        Map<String, Object> metadata,
        PromptExecutionMetadata promptExecutionMetadata
) {

    public String resolveRequestId() {
        if (requestId != null && !requestId.isBlank()) {
            return requestId;
        }
        if (securityEvent != null && securityEvent.getMetadata() != null) {
            Object rid = securityEvent.getMetadata().get("requestId");
            if (rid != null && !rid.toString().isBlank()) {
                return rid.toString();
            }
        }
        return securityEvent != null ? securityEvent.getEventId() : null;
    }
}
