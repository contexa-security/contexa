package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.std.rag.service.VectorOperations.VectorStoreException;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
public abstract class AbstractVectorLabService implements VectorOperations {

    protected final VectorStore vectorStore;
    protected final VectorStoreMetrics vectorStoreMetrics;

    protected AbstractVectorLabService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        this.vectorStore = vectorStore;
        this.vectorStoreMetrics = vectorStoreMetrics;
    }

    @Value("${spring.ai.vectorstore.lab.batch-size:50}")
    protected int labBatchSize;

    @Value("${spring.ai.vectorstore.lab.async-enabled:true}")
    protected boolean asyncEnabled;

    @Value("${spring.ai.vectorstore.lab.validation-enabled:true}")
    protected boolean validationEnabled;

    @Value("${spring.ai.vectorstore.lab.enrichment-enabled:true}")
    protected boolean enrichmentEnabled;

    @Value("${spring.ai.vectorstore.lab.async-thread-pool-size:4}")
    protected int asyncThreadPoolSize;

    @Value("${spring.ai.vectorstore.lab.top-k:100}")
    protected int defaultTopK;

    @Value("${spring.ai.vectorstore.lab.similarity-threshold:0.75}")
    protected double defaultSimilarityThreshold;

    private Executor asyncExecutor;

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @PostConstruct
    protected void initialize() {
        this.asyncExecutor = Executors.newFixedThreadPool(asyncThreadPoolSize);
    }

    @PreDestroy
    protected void cleanup() {
        if (asyncExecutor instanceof ExecutorService es) {
            es.shutdown();
            try {
                if (!es.awaitTermination(10, TimeUnit.SECONDS)) {
                    es.shutdownNow();
                }
            } catch (InterruptedException e) {
                es.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

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

            for (int i = 0; i < processedDocuments.size(); i += labBatchSize) {
                int end = Math.min(i + labBatchSize, processedDocuments.size());
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
    public final CompletableFuture<Void> storeDocumentAsync(Document document) {
        if (!asyncEnabled) {
            storeDocument(document);
            return CompletableFuture.completedFuture(null);
        }

        return CompletableFuture.runAsync(() -> storeDocument(document), asyncExecutor)
                .exceptionally(throwable -> {
                    log.error("[{}] Async single document storage failed", getLabName(), throwable);
                    throw new VectorStoreException("Async single document storage failed", throwable);
                });
    }

    @Override
    public final CompletableFuture<Void> storeDocumentsAsync(List<Document> documents) {
        if (!asyncEnabled) {
            storeDocuments(documents);
            return CompletableFuture.completedFuture(null);
        }

        return CompletableFuture.runAsync(() -> storeDocuments(documents), asyncExecutor)
                .exceptionally(throwable -> {
                    log.error("[{}] Async batch document storage failed", getLabName(), throwable);
                    throw new VectorStoreException("Async batch document storage failed", throwable);
                });
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
            labFilters.put("documentType", getDocumentType());
            labFilters.putAll(getLabSpecificFilters());

            int topK = labFilters.containsKey("topK")
                    ? ((Number) labFilters.get("topK")).intValue()
                    : defaultTopK;
            labFilters.remove("topK");

            Filter.Expression filterExpression = buildFilterExpression(labFilters);

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(defaultSimilarityThreshold)
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
    public final List<Document> searchByTimeRange(String query, LocalDateTime startTime,
                                                  LocalDateTime endTime, String documentType) {
        long start = System.currentTimeMillis();

        try {
            String finalDocumentType = documentType != null ? documentType : getDocumentType();

            FilterExpressionBuilder builder = new FilterExpressionBuilder();

            FilterExpressionBuilder.Op timeFilterOp = builder.and(
                    builder.gte("timestamp", startTime.format(ISO_FORMATTER)),
                    builder.lte("timestamp", endTime.format(ISO_FORMATTER))
            );

            Filter.Expression filter = builder.and(
                    timeFilterOp,
                    builder.eq("documentType", finalDocumentType)
            ).build();

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(defaultTopK)
                    .similarityThreshold(defaultSimilarityThreshold)
                    .filterExpression(filter)
                    .build();

            List<Document> results = vectorStore.similaritySearch(searchRequest);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH,
                        results.size(),
                        System.currentTimeMillis() - start);
            }

            return results;

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            }
            log.error("[{}] Time range search failed", getLabName(), e);
            throw new VectorStoreException("Time range search failed: " + e.getMessage(), e);
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

    @Override
    @Transactional
    public void updateDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }

        long startTime = System.currentTimeMillis();
        try {

            List<Document> processedDocuments = new ArrayList<>();
            for (Document doc : documents) {
                processedDocuments.add(preprocessDocument(doc));
            }

            List<String> documentIds = processedDocuments.stream()
                    .map(doc -> (String) doc.getMetadata().get("id"))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            if (!documentIds.isEmpty()) {
                vectorStore.delete(documentIds);
            }

            vectorStore.add(processedDocuments);

            for (Document doc : processedDocuments) {
                postProcessDocument(doc, OperationType.UPDATE);
            }

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.UPDATE,
                        processedDocuments.size(),
                        System.currentTimeMillis() - startTime);
            }

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.UPDATE, e);
            }
            log.error("[{}] Document update failed", getLabName(), e);
            throw new VectorStoreException("Document update failed: " + e.getMessage(), e);
        }
    }

    @Override
    public final Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("labName", getLabName());
        stats.put("documentType", getDocumentType());

        if (vectorStoreMetrics != null) {
            stats.putAll(vectorStoreMetrics.getLabStatistics(getLabName()));
        }

        return stats;
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

            metadata.put("documentType", getDocumentType());

            metadata.put("labName", getLabName());
            metadata.put("processingTimestamp", LocalDateTime.now().format(ISO_FORMATTER));

            Document processedDocument = new Document(document.getText(), metadata);

            if (validationEnabled) {
                validateLabSpecificDocument(processedDocument);
            }

            if (enrichmentEnabled) {
                processedDocument = enrichLabSpecificMetadata(processedDocument);
            }

            return processedDocument;

        } catch (Exception e) {
            log.error("[{}] Document preprocessing failed", getLabName(), e);
            throw new VectorStoreException("Document preprocessing failed: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private Filter.Expression buildFilterExpression(Map<String, Object> filters) {
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
            return ops.get(0).build();
        }

        FilterExpressionBuilder.Op combined = ops.get(0);
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
