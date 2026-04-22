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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Slf4j
public class UnifiedVectorService implements VectorOperations {

    private final PgVectorStoreProperties properties;
    private final VectorStoreCacheLayer cacheLayer;
    private final VectorStore vectorStore;
    private final ExecutorService vectorOperationExecutor;

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final int DEFAULT_MAX_CONCURRENT_VECTOR_OPERATIONS = 1;
    private static final int DEFAULT_VECTOR_BUSY_RETRY_ATTEMPTS = 5;
    private static final long DEFAULT_VECTOR_BUSY_INITIAL_BACKOFF_MS = 250L;
    private static final long DEFAULT_VECTOR_BUSY_MAX_BACKOFF_MS = 2_000L;
    private static final int VECTOR_BUSY_RETRY_ATTEMPTS = Math.max(1,
            Integer.getInteger("contexa.vector.busy-retry-attempts", DEFAULT_VECTOR_BUSY_RETRY_ATTEMPTS));
    private static final Semaphore VECTOR_OPERATION_GATE = new Semaphore(
            Math.max(1, Integer.getInteger("contexa.vector.max-concurrent-operations", DEFAULT_MAX_CONCURRENT_VECTOR_OPERATIONS)),
            true);

    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore) {
        this(properties, cacheLayer, vectorStore, ForkJoinPool.commonPool());
    }

    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            ExecutorService vectorOperationExecutor) {
        this.properties = properties;
        this.cacheLayer = cacheLayer;
        this.vectorStore = vectorStore;
        this.vectorOperationExecutor = vectorOperationExecutor != null ? vectorOperationExecutor : ForkJoinPool.commonPool();
    }

    @Override
    @Transactional
    public void storeDocument(Document document) {
        validateDocument(document);
        enrichStandardMetadata(document);
        executeWithBusyRetry(
                () -> {
                    vectorStore.add(List.of(document));
                    return null;
                },
                properties.getStoreTimeoutMs(),
                "store document",
                "Failed to store document");
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
            executeWithBusyRetry(
                    () -> {
                        vectorStore.add(immutableBatch);
                        return null;
                    },
                    properties.getStoreTimeoutMs(),
                    "store document batch",
                    "Failed to store document batch");
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
        return VectorFilterExpressionBuilder.buildEqualityExpression(filters);
    }

    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        return executeWithBusyRetry(
                () -> cacheLayer.similaritySearch(searchRequest),
                properties.getSearchTimeoutMs(),
                "similarity search",
                "Similarity search failed");
    }

    private <T> T executeWithBusyRetry(Callable<T> operation, long timeoutMs, String operationLabel, String failureMessage) {
        VectorStoreException lastFailure = null;
        for (int attempt = 0; attempt < VECTOR_BUSY_RETRY_ATTEMPTS; attempt++) {
            try {
                return executeWithinTimeout(operation, timeoutMs, operationLabel);
            } catch (VectorStoreCacheLayer.VectorSearchException vectorSearchException) {
                log.error("[UnifiedVectorService] {} failed", operationLabel, vectorSearchException);
                VectorStoreException mapped = new VectorStoreException(failureMessage, vectorSearchException);
                if (!isRetryableBusyFailure(vectorSearchException) || attempt >= VECTOR_BUSY_RETRY_ATTEMPTS - 1) {
                    throw mapped;
                }
                lastFailure = mapped;
                registerBusyRetry(attempt + 1, vectorSearchException, operationLabel);
            } catch (RuntimeException runtimeException) {
                log.error("[UnifiedVectorService] {} failed", operationLabel, runtimeException);
                VectorStoreException mapped = runtimeException instanceof VectorStoreException vectorStoreException
                        ? vectorStoreException
                        : new VectorStoreException(failureMessage, runtimeException);
                if (!isRetryableBusyFailure(runtimeException) || attempt >= VECTOR_BUSY_RETRY_ATTEMPTS - 1) {
                    throw mapped;
                }
                lastFailure = mapped;
                registerBusyRetry(attempt + 1, runtimeException, operationLabel);
            }
        }
        throw lastFailure != null ? lastFailure : new VectorStoreException(failureMessage);
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

    private void registerBusyRetry(int retryCount, Throwable throwable, String operationLabel) {
        SecurityEventTelemetryContext.put("vectorRetryCount", retryCount);
        SecurityEventTelemetryContext.put("vectorRetryReason", safeRetryMessage(throwable));
        long backoffMs = busyRetryBackoffMs(retryCount);
        log.warn("[UnifiedVectorService] Retrying {} after busy failure (attempt={}, backoff={}ms, reason={})",
                operationLabel,
                retryCount,
                backoffMs,
                safeRetryMessage(throwable));
        sleepQuietly(backoffMs);
    }

    private long busyRetryBackoffMs(int retryCount) {
        int normalizedRetry = Math.max(1, retryCount);
        long backoffMs = DEFAULT_VECTOR_BUSY_INITIAL_BACKOFF_MS << Math.max(0, normalizedRetry - 1);
        return Math.min(DEFAULT_VECTOR_BUSY_MAX_BACKOFF_MS, backoffMs);
    }

    private boolean isRetryableBusyFailure(Throwable throwable) {
        if (throwable == null) {
            return false;
        }
        String message = throwable.getMessage();
        if (message != null) {
            String normalized = message.toLowerCase(Locale.ROOT);
            if (normalized.contains("maximum pending requests exceeded")
                    || normalized.contains("server busy, please try again")
                    || normalized.contains("transientaiexception")
                    || normalized.contains("http 503")) {
                return true;
            }
        }
        return isRetryableBusyFailure(throwable.getCause());
    }

    private String safeRetryMessage(Throwable throwable) {
        if (throwable == null) {
            return "unknown";
        }
        if (throwable.getMessage() != null && !throwable.getMessage().isBlank()) {
            return throwable.getMessage();
        }
        return throwable.getClass().getSimpleName();
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    private <T> T executeWithinTimeout(Callable<T> operation, long timeoutMs, String operationLabel) {
        SecurityEventTelemetryContext.putIfAbsent("vectorRetryCount", 0L);
        Future<T> future = null;
        long effectiveTimeoutMs = Math.max(100L, timeoutMs);
        boolean permitAcquired = false;
        try {
            acquireVectorOperationPermit(operationLabel);
            permitAcquired = true;
            future = vectorOperationExecutor.submit(operation);
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
            if (permitAcquired) {
                VECTOR_OPERATION_GATE.release();
            }
        }
    }

    private void acquireVectorOperationPermit(String operationLabel) throws InterruptedException {
        VECTOR_OPERATION_GATE.acquire();
        SecurityEventTelemetryContext.put("vectorOperationGatePermitsRemaining", VECTOR_OPERATION_GATE.availablePermits());
        SecurityEventTelemetryContext.put("vectorOperationLabel", operationLabel);
    }
}
