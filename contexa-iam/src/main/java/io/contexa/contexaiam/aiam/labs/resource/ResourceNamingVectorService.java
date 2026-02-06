package io.contexa.contexaiam.aiam.labs.resource;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class ResourceNamingVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public ResourceNamingVectorService(VectorStore vectorStore,
                                      @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }

    @Override
    protected String getLabName() {
        return "ResourceNaming";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.RESOURCE_NAMING.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        return document;
    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("resourceCategory") &&
            !metadata.containsKey("resourcePath") &&
            !metadata.containsKey("organizationId")) {
            throw new IllegalArgumentException(
                "Resource Naming document must contain at least one of: resourceCategory, resourcePath, organizationId");
        }

        String text = document.getText();
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("Resource naming content is empty");
        }

        if (text.length() > 500) {
            throw new IllegalArgumentException("Resource naming content is too long (maximum 500 characters)");
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public void storeNamingRequest(ResourceNamingSuggestionRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("organizationId", request.getContext().getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.RESOURCE_NAMING_REQUEST.getValue());
            metadata.put("requestId", UUID.randomUUID().toString());

            String requestText = String.format(
                "Resource naming request from organization %s: %d resources",
                request.getContext().getOrganizationId(),
                request.getResources().size()
            );

            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] Naming request storage failed", e);
            throw new VectorStoreException("Naming request storage failed: " + e.getMessage(), e);
        }
    }

    public void storeNamingResult(ResourceNamingSuggestionRequest request, ResourceNamingSuggestionResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("organizationId", request.getContext().getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.RESOURCE_NAMING_RESULT.getValue());

            String resultText = String.format(
                "Resource naming result: success=%d, failed=%d, processingTime=%dms",
                response.getStats().getSuccessfullyProcessed(),
                response.getStats().getFailed(),
                response.getStats().getProcessingTimeMs()
            );

            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] Naming result storage failed", e);
            throw new VectorStoreException("Naming result storage failed: " + e.getMessage(), e);
        }
    }

    public List<Document> findSimilarNamings(String identifier, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("topK", topK);
        return searchSimilar(identifier, filters);
    }
}
