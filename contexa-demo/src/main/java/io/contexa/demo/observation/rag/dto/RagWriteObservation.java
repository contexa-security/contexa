package io.contexa.demo.observation.rag.dto;

import io.contexa.demo.observation.learning.dto.LearningSource;
import java.time.Instant;
import java.util.UUID;

public record RagWriteObservation(
        UUID id,
        LearningSource source,
        Instant returnedAt,
        RagDocumentFingerprint submitted,
        String failureType) {
}
