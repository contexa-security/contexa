package io.contexa.demo.observation.rag.dto;

public record RagDocumentFingerprint(
        String documentId,
        String contentSha256,
        Integer contentBytes,
        String eventId,
        String documentType) {
}
