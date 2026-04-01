package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.VectorOperations.VectorStoreException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

@Slf4j
public class UnifiedVectorService implements VectorOperations {

    private final PgVectorStoreProperties properties;
    private final VectorStoreCacheLayer cacheLayer;
    private final VectorStore vectorStore;

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore) {
        this.properties = properties;
        this.cacheLayer = cacheLayer;
        this.vectorStore = vectorStore;
    }

    @Override
    @Transactional
    public void storeDocument(Document document) {
        validateDocument(document);
        enrichStandardMetadata(document);
        executeWithinTimeout(
                () -> {
                    vectorStore.add(List.of(document));
                    return null;
                },
                properties.getStoreTimeoutMs(),
                "store document");
        cacheLayer.invalidateAll();
    }

    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }

        for (Document doc : documents) {
            validateDocument(doc);
            enrichStandardMetadata(doc);
        }

        int batchSize = properties.getBatchSize();
        for (int i = 0; i < documents.size(); i += batchSize) {
            int end = Math.min(i + batchSize, documents.size());
            List<Document> batch = documents.subList(i, end);
            List<Document> immutableBatch = List.copyOf(batch);
            executeWithinTimeout(
                    () -> {
                        vectorStore.add(immutableBatch);
                        return null;
                    },
                    properties.getStoreTimeoutMs(),
                    "store document batch");
        }

        cacheLayer.invalidateAll();
    }


    @Override
    public List<Document> searchSimilar(String query) {
        return searchSimilar(SearchRequest.builder()
                .query(query)
                .topK(properties.getTopK())
                .similarityThreshold(properties.getSimilarityThreshold())
                .build());
    }

    @Override
    public List<Document> searchSimilar(String query, Map<String, Object> filters) {
        SearchRequest.Builder builder = SearchRequest.builder()
                .query(query)
                .topK(properties.getTopK())
                .similarityThreshold(properties.getSimilarityThreshold());

        if (filters != null && !filters.isEmpty()) {
            String filterExpression = buildFilterExpression(filters);
            builder.filterExpression(filterExpression);
        }

        return searchSimilar(builder.build());
    }

    private String buildFilterExpression(Map<String, Object> filters) {
        StringJoiner joiner = new StringJoiner(" && ");
        for (Map.Entry<String, Object> entry : filters.entrySet()) {
            joiner.add(entry.getKey() + " == '" + entry.getValue() + "'");
        }
        return joiner.toString();
    }

    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        try {
            return executeWithinTimeout(
                    () -> cacheLayer.similaritySearch(searchRequest),
                    properties.getSearchTimeoutMs(),
                    "similarity search");

        } catch (VectorStoreCacheLayer.VectorSearchException vectorSearchException) {
            log.error("[UnifiedVectorService] Cache-backed similarity search failed", vectorSearchException);
            throw new VectorStoreException("Similarity search failed", vectorSearchException);
        } catch (Exception e) {
            log.error("[UnifiedVectorService] Error during similarity search", e);
            throw new VectorStoreException("Similarity search failed", e);
        }
    }

    @Override
    @Transactional
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            return;
        }

        try {
            vectorStore.delete(documentIds);
            cacheLayer.invalidateAll();
        } catch (Exception e) {
            log.error("[UnifiedVectorService] Failed to delete documents", e);
            throw new VectorStoreException("Failed to delete documents", e);
        }
    }

    private void validateDocument(Document document) {
        if (document == null) {
            throw new VectorStoreException("Document cannot be null");
        }

        if (document.getText() == null || document.getText().isEmpty()) {
            throw new VectorStoreException("Document text cannot be empty");
        }
    }

    private void enrichStandardMetadata(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("id")) {
            metadata.put("id", UUID.randomUUID().toString());
        }

        if (!metadata.containsKey("timestamp")) {
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
        }

        if (!metadata.containsKey("documentType")) {
            metadata.put("documentType", VectorDocumentType.STANDARD.getValue());
        }

        if (!metadata.containsKey("version")) {
            metadata.put("version", "1.0");
        }
    }

    private <T> T executeWithinTimeout(Callable<T> operation, long timeoutMs, String operationLabel) {
        SecurityEventTelemetryContext.putIfAbsent("vectorRetryCount", 0L);
        var executor = Executors.newVirtualThreadPerTaskExecutor();
        CompletableFuture<T> future = null;
        long effectiveTimeoutMs = Math.max(100L, timeoutMs);
        try {
            future = CompletableFuture.supplyAsync(() -> {
                try {
                    return operation.call();
                } catch (RuntimeException runtimeException) {
                    throw runtimeException;
                } catch (Exception checkedException) {
                    throw new RuntimeException(checkedException);
                }
            }, executor);
            return future.get(effectiveTimeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeoutException) {
            future.cancel(true);
            throw new VectorStoreException(
                    String.format("Vector store %s timed out after %dms", operationLabel, effectiveTimeoutMs),
                    timeoutException);
        } catch (ExecutionException executionException) {
            Throwable cause = executionException.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new VectorStoreException("Vector store " + operationLabel + " failed", cause);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new VectorStoreException("Vector store " + operationLabel + " interrupted", interruptedException);
        } finally {
            executor.shutdownNow();
        }
    }
}
