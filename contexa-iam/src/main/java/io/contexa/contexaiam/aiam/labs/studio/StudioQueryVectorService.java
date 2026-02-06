package io.contexa.contexaiam.aiam.labs.studio;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import org.springframework.ai.vectorstore.VectorStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class StudioQueryVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public StudioQueryVectorService(VectorStore vectorStore,
                                   @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }

    @Override
    protected String getLabName() {
        return "StudioQuery";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.STUDIO_QUERY.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
     return document;
    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("userId") &&
            !metadata.containsKey("naturalLanguageQuery")) {
            throw new IllegalArgumentException(
                "Studio Query document must contain at least one of: userId, queryType, naturalLanguageQuery");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 5) {
            throw new IllegalArgumentException("Query content is too short (minimum 5 characters required)");
        }

        if (text.length() > 5000) {
            throw new IllegalArgumentException("Query content is too long (maximum 5000 characters)");
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public List<Document> findSimilarQueries(String query, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("topK", topK);
        return searchSimilar(query, filters);
    }

    public void storeQueryRequest(StudioQueryRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("naturalLanguageQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.STUDIO_QUERY.getValue());
            metadata.put("requestId", UUID.randomUUID().toString());

            String queryText = String.format(
                    "사용자 %s의 자연어 질의: %s",
                    request.getUserId(),
                    request.getNaturalLanguageQuery()
            );

            Document queryDoc = new Document(queryText, metadata);
            storeDocument(queryDoc);

        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 질의 요청 저장 실패", e);
            throw new VectorStoreException("질의 요청 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeQueryResult(String queryId, String result) {
        try {
            String safeQueryId = queryId != null ? queryId : "unknown";
            String safeResult = result != null ?
                    result.substring(0, Math.min(1000, result.length())) : "";

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", VectorDocumentType.STUDIO_QUERY_RESULT.getValue());
            metadata.put("queryId", safeQueryId);
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            Document doc = new Document(safeResult, metadata);
            storeDocument(doc);

        } catch (Exception e) {
            log.error("Studio query result save failed", e);
        }
    }
}
