package io.contexa.contexacore.std.security;

import org.springframework.ai.document.Document;

import java.util.List;
import java.util.Set;

public record AuthorizedPromptContext(
        List<Document> documents,
        int requestedDocumentCount,
        int allowedDocumentCount,
        int deniedDocumentCount,
        String retrievalPurpose,
        List<String> deniedReasons,
        PurposeBoundRetrievalPolicy retrievalPolicy,
        List<ContextProvenanceRecord> provenanceRecords,
        List<AuthorizedPromptContextItem> contextItems) {

    public AuthorizedPromptContext {
        documents = documents == null ? List.of() : List.copyOf(documents);
        deniedReasons = deniedReasons == null ? List.of() : List.copyOf(deniedReasons);
        retrievalPurpose = retrievalPurpose == null ? "general_context" : retrievalPurpose;
        retrievalPolicy = retrievalPolicy == null
                ? new PurposeBoundRetrievalPolicy(null, null, null, retrievalPurpose, Set.of())
                : retrievalPolicy;
        provenanceRecords = provenanceRecords == null ? List.of() : List.copyOf(provenanceRecords);
        contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
    }

    public AuthorizedPromptContext(
            List<Document> documents,
            int requestedDocumentCount,
            int allowedDocumentCount,
            int deniedDocumentCount,
            String retrievalPurpose,
            List<String> deniedReasons) {
        this(
                documents,
                requestedDocumentCount,
                allowedDocumentCount,
                deniedDocumentCount,
                retrievalPurpose,
                deniedReasons,
                new PurposeBoundRetrievalPolicy(null, null, null, retrievalPurpose, Set.of()),
                List.of(),
                List.of());
    }
}
