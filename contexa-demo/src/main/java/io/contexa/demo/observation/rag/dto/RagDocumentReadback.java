package io.contexa.demo.observation.rag.dto;

import java.time.Instant;

public record RagDocumentReadback(
        String state,
        Instant readAt,
        RagDocumentFingerprint document,
        Boolean embeddingPresent,
        String rowSha256) {
}
