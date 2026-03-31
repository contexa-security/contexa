package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * sandbox 전용 retrieval audit 저장소.
 *
 * Layer1 analyzeWithContext 실행 동안 현재 event/requestId를 thread-local로 붙잡고,
 * 그 안에서 일어나는
 * - vector document 저장
 * - similarity search
 * - prompt authorization
 * 결과를 event 기준으로 누적 기록한다.
 *
 * production 코드 변경 없이 "relatedDocuments가 왜 0인가"를 단계별로 분해하는 용도다.
 */
public class SandboxRetrievalAuditStore {

    private final ThreadLocal<ActiveLayer1Context> activeContext = new ThreadLocal<>();
    private final ConcurrentMap<String, MutableAudit> auditByEventId = new ConcurrentHashMap<>();

    public void begin(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            activeContext.remove();
            return;
        }
        String requestId = extractRequestId(event);
        activeContext.set(new ActiveLayer1Context(event.getEventId(), requestId));
        auditByEventId.computeIfAbsent(event.getEventId(), ignored -> new MutableAudit(requestId, event.getEventId()));
    }

    public void end() {
        activeContext.remove();
    }

    public void clearAll() {
        activeContext.remove();
        auditByEventId.clear();
    }

    public void recordStore(Document document) {
        MutableAudit audit = currentAudit();
        if (audit == null || document == null) {
            return;
        }
        synchronized (audit) {
            audit.storedDocumentCount++;
            audit.storedDocuments.add(StoredDocumentRecord.from(document));
        }
    }

    public void recordSearch(SearchRequest searchRequest, List<Document> rawDocuments) {
        MutableAudit audit = currentAudit();
        if (audit == null || searchRequest == null) {
            return;
        }
        synchronized (audit) {
            audit.searchQuery = searchRequest.getQuery();
            audit.topK = searchRequest.getTopK();
            audit.similarityThreshold = searchRequest.getSimilarityThreshold();
            audit.filterExpression = searchRequest.getFilterExpression() != null
                    ? String.valueOf(searchRequest.getFilterExpression())
                    : null;
            audit.rawRetrievedCount = rawDocuments != null ? rawDocuments.size() : 0;
            audit.rawRetrievedDocuments = convertDocuments(rawDocuments);
        }
    }

    public void recordAuthorization(SecurityEvent event, String retrievalPurpose, List<Document> requestedDocuments,
                                    AuthorizedPromptContext authorizedPromptContext) {
        MutableAudit audit = resolveAudit(event);
        if (audit == null) {
            return;
        }
        synchronized (audit) {
            audit.retrievalPurpose = retrievalPurpose;
            audit.authorizeRequestedCount = requestedDocuments != null ? requestedDocuments.size() : 0;
            audit.authorizeAllowedCount = authorizedPromptContext != null ? authorizedPromptContext.allowedDocumentCount() : 0;
            audit.authorizeDeniedCount = authorizedPromptContext != null ? authorizedPromptContext.deniedDocumentCount() : 0;
            audit.authorizeDeniedReasons = authorizedPromptContext != null
                    ? List.copyOf(authorizedPromptContext.deniedReasons())
                    : List.of();
            audit.authorizedDocuments = authorizedPromptContext != null
                    ? convertDocuments(authorizedPromptContext.documents())
                    : List.of();
        }
    }

    public SandboxRetrievalAuditSnapshot snapshot(SecurityEvent event) {
        MutableAudit audit = resolveAudit(event);
        if (audit == null) {
            return null;
        }
        synchronized (audit) {
            return audit.toSnapshot();
        }
    }

    private MutableAudit currentAudit() {
        ActiveLayer1Context current = activeContext.get();
        if (current == null || !StringUtils.hasText(current.eventId())) {
            return null;
        }
        return auditByEventId.computeIfAbsent(
                current.eventId(),
                ignored -> new MutableAudit(current.requestId(), current.eventId()));
    }

    private MutableAudit resolveAudit(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            return currentAudit();
        }
        return auditByEventId.computeIfAbsent(
                event.getEventId(),
                ignored -> new MutableAudit(extractRequestId(event), event.getEventId()));
    }

    private String extractRequestId(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object requestId = event.getMetadata().get("requestId");
        if (requestId instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        Object correlationId = event.getMetadata().get("correlationId");
        if (correlationId instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        return null;
    }

    private static List<RetrievedDocumentRecord> convertDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return List.of();
        }
        List<RetrievedDocumentRecord> converted = new ArrayList<>(documents.size());
        for (Document document : documents) {
            converted.add(RetrievedDocumentRecord.from(document));
        }
        return List.copyOf(converted);
    }

    private record ActiveLayer1Context(String eventId, String requestId) {
    }

    public record StoredDocumentRecord(
            String documentType,
            String sourceType,
            String accessScope,
            String artifactId,
            String userId,
            String retrievalPurpose,
            String requestPath,
            String summaryText) {

        static StoredDocumentRecord from(Document document) {
            Map<String, Object> metadata = document != null && document.getMetadata() != null
                    ? document.getMetadata()
                    : Map.of();
            String text = document != null ? document.getText() : null;
            String summary = text != null && text.length() > 220 ? text.substring(0, 220) + "..." : text;
            return new StoredDocumentRecord(
                    asText(metadata, VectorDocumentMetadata.DOCUMENT_TYPE),
                    asText(metadata, VectorDocumentMetadata.SOURCE_TYPE),
                    asText(metadata, VectorDocumentMetadata.ACCESS_SCOPE),
                    asText(metadata, VectorDocumentMetadata.ARTIFACT_ID),
                    asText(metadata, VectorDocumentMetadata.USER_ID),
                    asText(metadata, VectorDocumentMetadata.RETRIEVAL_PURPOSE),
                    asText(metadata, "requestPath"),
                    summary);
        }
    }

    public record RetrievedDocumentRecord(
            String documentType,
            String sourceType,
            String accessScope,
            String artifactId,
            String userId,
            String retrievalPurpose,
            String authorizationDecision,
            String promptSafetyDecision,
            String memoryReadDecision,
            Double similarityScore,
            String requestPath,
            String summaryText,
            Map<String, Object> metadata) {

        static RetrievedDocumentRecord from(Document document) {
            Map<String, Object> sourceMetadata = document != null && document.getMetadata() != null
                    ? document.getMetadata()
                    : Map.of();
            Map<String, Object> copiedMetadata = new LinkedHashMap<>(sourceMetadata);
            String text = document != null ? document.getText() : null;
            String summary = text != null && text.length() > 220 ? text.substring(0, 220) + "..." : text;
            Double similarityScore = document != null && document.getScore() != null
                    ? document.getScore()
                    : asDouble(sourceMetadata.get(VectorDocumentMetadata.SIMILARITY_SCORE));
            return new RetrievedDocumentRecord(
                    asText(sourceMetadata, VectorDocumentMetadata.DOCUMENT_TYPE),
                    asText(sourceMetadata, VectorDocumentMetadata.SOURCE_TYPE),
                    asText(sourceMetadata, VectorDocumentMetadata.ACCESS_SCOPE),
                    asText(sourceMetadata, VectorDocumentMetadata.ARTIFACT_ID),
                    asText(sourceMetadata, VectorDocumentMetadata.USER_ID),
                    asText(sourceMetadata, VectorDocumentMetadata.RETRIEVAL_PURPOSE),
                    asText(sourceMetadata, VectorDocumentMetadata.AUTHORIZATION_DECISION),
                    asText(sourceMetadata, VectorDocumentMetadata.PROMPT_SAFETY_DECISION),
                    asText(sourceMetadata, VectorDocumentMetadata.MEMORY_READ_DECISION),
                    similarityScore,
                    asText(sourceMetadata, "requestPath"),
                    summary,
                    Map.copyOf(copiedMetadata));
        }
    }

    private static String asText(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        return value != null ? String.valueOf(value) : null;
    }

    private static Double asDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static final class MutableAudit {
        private final String requestId;
        private final String eventId;
        private int storedDocumentCount;
        private final List<StoredDocumentRecord> storedDocuments = new ArrayList<>();
        private String searchQuery;
        private Integer topK;
        private Double similarityThreshold;
        private String filterExpression;
        private int rawRetrievedCount;
        private List<RetrievedDocumentRecord> rawRetrievedDocuments = List.of();
        private String retrievalPurpose;
        private int authorizeRequestedCount;
        private int authorizeAllowedCount;
        private int authorizeDeniedCount;
        private List<String> authorizeDeniedReasons = List.of();
        private List<RetrievedDocumentRecord> authorizedDocuments = List.of();

        private MutableAudit(String requestId, String eventId) {
            this.requestId = requestId;
            this.eventId = eventId;
        }

        private SandboxRetrievalAuditSnapshot toSnapshot() {
            return new SandboxRetrievalAuditSnapshot(
                    requestId,
                    eventId,
                    storedDocumentCount,
                    List.copyOf(storedDocuments),
                    searchQuery,
                    topK,
                    similarityThreshold,
                    filterExpression,
                    rawRetrievedCount,
                    rawRetrievedDocuments,
                    retrievalPurpose,
                    authorizeRequestedCount,
                    authorizeAllowedCount,
                    authorizeDeniedCount,
                    authorizeDeniedReasons,
                    authorizedDocuments);
        }
    }
}
