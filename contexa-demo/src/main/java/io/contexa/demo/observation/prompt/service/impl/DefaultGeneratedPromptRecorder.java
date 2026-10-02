package io.contexa.demo.observation.prompt.service.impl;

import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;
import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import io.contexa.demo.observation.prompt.service.GeneratedPromptRecorder;
import io.contexa.demo.observation.prompt.service.PromptContextProjection;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
@Profile("contexa")
public class DefaultGeneratedPromptRecorder implements GeneratedPromptRecorder {

    private final EngineObservationSink sink;
    private final DocumentCodec documents;
    private final PromptContextProjection contextProjection;

    public DefaultGeneratedPromptRecorder(EngineObservationSink sink, DocumentCodec documents,
            PromptContextProjection contextProjection) {
        this.sink = sink;
        this.documents = documents;
        this.contextProjection = contextProjection;
    }

    @Override
    public void record(SealedEvidencePromptSnapshot snapshot) {
        if (snapshot == null || snapshot.securityEvent() == null) {
            return;
        }
        UUID requestId;
        try {
            requestId = UUID.fromString(snapshot.resolveRequestId());
        } catch (IllegalArgumentException unsupported) {
            return;
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("captureBoundary", "PROMPT_GENERATOR_RETURN");
        payload.put("transportEvidence", false);
        payload.put("contextEvidence", contextProjection.project(snapshot));
        payload.put("eventId", snapshot.securityEvent().getEventId());
        Object generation = snapshot.securityEvent().getMetadata().get("eventProcessingOwnerToken");
        if (generation != null) {
            payload.put("eventProcessingOwnerToken", generation.toString());
        }
        addPrompt(payload, "system", snapshot.systemPrompt(), snapshot.securityEvent().getSessionId());
        addPrompt(payload, "user", snapshot.userPrompt(), snapshot.securityEvent().getSessionId());
        sink.offer(new EngineObservation(UUID.randomUUID(), requestId, "GENERATED_PROMPT", snapshot.capturedAt(), payload));
    }

    private void addPrompt(Map<String, Object> payload, String key, String text, String sessionId) {
        if (text == null) {
            return;
        }
        payload.put(key + "OriginalSha256", documents.hash(text));
        String sanitized = SensitiveValueSanitizer.sanitizeText(text);
        if (sessionId != null && !sessionId.isBlank()) {
            sanitized = sanitized.replace(sessionId, "[REDACTED_SESSION_ID]");
        }
        payload.put(key + "SanitizedText", sanitized.substring(0, Math.min(sanitized.length(), 65536)));
        payload.put(key + "Truncated", sanitized.length() > 65536);
        payload.put(key + "Redacted", !sanitized.equals(text));
    }
}
