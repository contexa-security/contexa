package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

/**
 * sandbox full-stack replay에서 relatedDocuments 생성 경로를 분해해서 남기는 진단 snapshot.
 *
 * 목적:
 * 1. vector store에 문서가 저장되었는지
 * 2. similarity search가 몇 건을 원시 반환했는지
 * 3. prompt authorization 단계에서 몇 건이 허용/거부되었는지
 *
 * 즉 relatedDocuments=0 이면
 * - 저장이 안 된 것인지
 * - 검색이 0건인 것인지
 * - 검색은 됐지만 authorize 후 0건이 된 것인지
 * 를 실측값으로 분리하기 위한 sandbox 전용 데이터다.
 */
public record SandboxRetrievalAuditSnapshot(
        String requestId,
        String eventId,
        int storedDocumentCount,
        List<SandboxRetrievalAuditStore.StoredDocumentRecord> storedDocuments,
        String searchQuery,
        Integer topK,
        Double similarityThreshold,
        String filterExpression,
        int rawRetrievedCount,
        List<SandboxRetrievalAuditStore.RetrievedDocumentRecord> rawRetrievedDocuments,
        String retrievalPurpose,
        int authorizeRequestedCount,
        int authorizeAllowedCount,
        int authorizeDeniedCount,
        List<String> authorizeDeniedReasons,
        List<SandboxRetrievalAuditStore.RetrievedDocumentRecord> authorizedDocuments) {

    public SandboxRetrievalAuditSnapshot {
        storedDocuments = storedDocuments == null ? List.of() : List.copyOf(storedDocuments);
        rawRetrievedDocuments = rawRetrievedDocuments == null ? List.of() : List.copyOf(rawRetrievedDocuments);
        authorizeDeniedReasons = authorizeDeniedReasons == null ? List.of() : List.copyOf(authorizeDeniedReasons);
        authorizedDocuments = authorizedDocuments == null ? List.of() : List.copyOf(authorizedDocuments);
    }
}
