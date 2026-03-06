package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.rag.service.VectorOperations.VectorStoreException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public abstract class AbstractVectorLabService implements VectorOperations {

    protected final VectorStore vectorStore;
    protected final VectorStoreMetrics vectorStoreMetrics;
    protected final ContexaRagProperties ragProperties;

    protected AbstractVectorLabService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
            ContexaRagProperties ragProperties) {
        this.vectorStore = vectorStore;
        this.vectorStoreMetrics = vectorStoreMetrics;
        this.ragProperties = ragProperties;
    }

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    protected abstract String getLabName();

    protected abstract String getDocumentType();

    protected abstract Document enrichLabSpecificMetadata(Document document);

    protected abstract void validateLabSpecificDocument(Document document);

    protected void postProcessDocument(Document document, OperationType operationType) {

    }

    @Override
    @Transactional
    public void storeDocument(Document document) {
        long startTime = System.currentTimeMillis();

        try {

            Document processedDocument = preprocessDocument(document);
            vectorStore.add(List.of(processedDocument));
            postProcessDocument(processedDocument, OperationType.STORE);
            long duration = System.currentTimeMillis() - startTime;
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.STORE, 1, duration);

                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("lab_name", getLabName());
                eventMetadata.put("operation_type", OperationType.STORE.name());
                eventMetadata.put("document_count", 1);
                eventMetadata.put("duration", duration);
                vectorStoreMetrics.recordEvent("vector_store_operation", eventMetadata);
            }

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.STORE, e);
            }
            log.error("[{}] Single document storage failed", getLabName(), e);
            throw new VectorStoreException("Single document storage failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }

        long startTime = System.currentTimeMillis();

        try {

            List<Document> processedDocuments = new ArrayList<>();
            for (Document doc : documents) {
                processedDocuments.add(preprocessDocument(doc));
            }

            for (int i = 0; i < processedDocuments.size(); i += ragProperties.getLab().getBatchSize()) {
                int end = Math.min(i + ragProperties.getLab().getBatchSize(), processedDocuments.size());
                List<Document> batch = processedDocuments.subList(i, end);
                vectorStore.add(batch);
            }

            for (Document doc : processedDocuments) {
                postProcessDocument(doc, OperationType.STORE);
            }

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.STORE,
                        processedDocuments.size(),
                        System.currentTimeMillis() - startTime);
            }

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.STORE, e);
            }
            log.error("[{}] Batch document storage failed", getLabName(), e);
            throw new VectorStoreException("Batch document storage failed: " + e.getMessage(), e);
        }
    }

    @Override
    public final List<Document> searchSimilar(String query) {
        return searchSimilar(query, Collections.emptyMap());
    }

    @Override
    public final List<Document> searchSimilar(String query, Map<String, Object> filters) {
        long startTime = System.currentTimeMillis();

        try {

            Map<String, Object> labFilters = new HashMap<>(filters);
            labFilters.putAll(getLabSpecificFilters());

            int topK = labFilters.containsKey("topK")
                    ? ((Number) labFilters.get("topK")).intValue()
                    : ragProperties.getLab().getTopK();
            labFilters.remove("topK");

            Filter.Expression filterExpression = buildFilterExpression(labFilters);

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(ragProperties.getLab().getSimilarityThreshold())
                    .filterExpression(filterExpression)
                    .build();

            List<Document> results = vectorStore.similaritySearch(searchRequest);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH,
                        results.size(),
                        System.currentTimeMillis() - startTime);
            }

            return results;

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            }
            log.error("[{}] Search failed: query='{}'", getLabName(), query, e);
            throw new VectorStoreException("Search failed: " + e.getMessage(), e);
        }
    }

    @Override
    public final List<Document> searchSimilar(SearchRequest searchRequest) {
        long startTime = System.currentTimeMillis();

        try {
            List<Document> results = vectorStore.similaritySearch(searchRequest);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH,
                        results.size(),
                        System.currentTimeMillis() - startTime);
            }

            return results;

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            }
            log.error("[{}] Advanced search failed", getLabName(), e);
            throw new VectorStoreException("Advanced search failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Transactional
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            return;
        }

        long startTime = System.currentTimeMillis();

        try {
            vectorStore.delete(documentIds);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.DELETE,
                        documentIds.size(),
                        System.currentTimeMillis() - startTime);
            }

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.DELETE, e);
            }
            log.error("[{}] Document deletion failed", getLabName(), e);
            throw new VectorStoreException("Document deletion failed: " + e.getMessage(), e);
        }
    }

    private Document preprocessDocument(Document document) {
        try {

            if (document == null) {
                throw new IllegalArgumentException("Document cannot be null");
            }

            if (document.getText() == null || document.getText().trim().isEmpty()) {
                throw new IllegalArgumentException("Document content cannot be empty");
            }

            Map<String, Object> metadata = new HashMap<>(document.getMetadata());

            if (!metadata.containsKey("id")) {
                metadata.put("id", UUID.randomUUID().toString());
            }

            if (!metadata.containsKey("timestamp")) {
                metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            }

            if (!metadata.containsKey("documentType")) {
                metadata.put("documentType", getDocumentType());
            }

            metadata.put("labName", getLabName());
            metadata.put("processingTimestamp", LocalDateTime.now().format(ISO_FORMATTER));

            Document processedDocument = new Document(document.getText(), metadata);

            if (ragProperties.getLab().isValidationEnabled()) {
                validateLabSpecificDocument(processedDocument);
            }

            if (ragProperties.getLab().isEnrichmentEnabled()) {
                processedDocument = enrichLabSpecificMetadata(processedDocument);
            }

            // Remove null values from metadata (VectorStore requirement)
            Map<String, Object> sanitizedMetadata = new HashMap<>(processedDocument.getMetadata());
            sanitizedMetadata.entrySet().removeIf(entry -> entry.getValue() == null);
            processedDocument = new Document(processedDocument.getText(), sanitizedMetadata);

            return processedDocument;

        } catch (Exception e) {
            log.error("[{}] Document preprocessing failed", getLabName(), e);
            throw new VectorStoreException("Document preprocessing failed: " + e.getMessage(), e);
        }
    }

    protected Filter.Expression buildFilterExpression(Map<String, Object> filters) {
        if (filters == null || filters.isEmpty()) {
            return null;
        }

        FilterExpressionBuilder builder = new FilterExpressionBuilder();
        List<FilterExpressionBuilder.Op> ops = new ArrayList<>();

        for (Map.Entry<String, Object> entry : filters.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof String) {
                ops.add(builder.eq(key, value));
            } else if (value instanceof Number) {
                ops.add(builder.eq(key, value));
            } else if (value instanceof List) {
                ops.add(builder.in(key, (List<?>) value));
            } else if (value instanceof Map) {
                Map<String, Object> rangeMap = (Map<String, Object>) value;
                if (rangeMap.containsKey("gte") && rangeMap.containsKey("lte")) {
                    ops.add(builder.and(
                            builder.gte(key, rangeMap.get("gte")),
                            builder.lte(key, rangeMap.get("lte"))
                    ));
                }
            }
        }

        if (ops.isEmpty()) {
            return null;
        }

        if (ops.size() == 1) {
            return ops.getFirst().build();
        }

        FilterExpressionBuilder.Op combined = ops.getFirst();
        for (int i = 1; i < ops.size(); i++) {
            combined = builder.and(combined, ops.get(i));
        }
        return combined.build();
    }

    protected Map<String, Object> getLabSpecificFilters() {
        return Collections.emptyMap();
    }

    public enum OperationType {
        STORE, SEARCH, UPDATE, DELETE
    }
}
