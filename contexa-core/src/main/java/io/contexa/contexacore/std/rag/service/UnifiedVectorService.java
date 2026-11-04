/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.ContentFormatter;
import org.springframework.ai.document.DefaultContentFormatter;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.VectorOperations.VectorStoreException;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import org.springframework.beans.factory.DisposableBean;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Slf4j
public class UnifiedVectorService implements VectorOperations, DisposableBean {

    private final PgVectorStoreProperties properties;
    private final VectorStoreCacheLayer cacheLayer;
    private final VectorStore vectorStore;
    private final PastRecordQuery pastRecordQuery;
    private final ExecutorService vectorOperationExecutor;
    private final boolean ownsExecutor;
    /** Keeps the documents whose store failed and stores them again (BR-C4, QF-8); null when the retry is off. */
    private final FailedDocumentRetrier failedStores;
    /** BR-S2: where the embedding model of the stored documents is read from, once; null when it is not known. */
    private volatile Supplier<String> embeddingModelSource;
    private volatile String embeddingModel;
    private volatile boolean embeddingModelResolved;

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    /**
     * BR-S2: the text an embedding model embeds is the document's, without the embedding model key. A provider that
     * embeds the metadata with the text (Spring AI's OpenAI embedding, MetadataMode.EMBED) embeds what it did before.
     */
    private static final ContentFormatter EMBEDDING_CONTENT = DefaultContentFormatter.builder()
            .withExcludedEmbedMetadataKeys(VectorDocumentMetadata.EMBEDDING_MODEL)
            .build();
    /** The metadata key of the user a document belongs to, as the account purge reads it. */
    private static final String USER_METADATA_KEY = VectorDocumentMetadata.USER_ID;
    private static final int DEFAULT_VECTOR_BUSY_RETRY_ATTEMPTS = 5;
    private static final long DEFAULT_VECTOR_BUSY_INITIAL_BACKOFF_MS = 250L;
    private static final long DEFAULT_VECTOR_BUSY_MAX_BACKOFF_MS = 2_000L;
    private static final int VECTOR_BUSY_RETRY_ATTEMPTS = Math.max(1,
            Integer.getInteger("contexa.vector.busy-retry-attempts", DEFAULT_VECTOR_BUSY_RETRY_ATTEMPTS));

    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore) {
        this(properties, cacheLayer, vectorStore, createDefaultExecutor(), true, PastRecordQuery.unavailable(),
                null, null, null, null);
    }

    private static ExecutorService createDefaultExecutor() {
        return new ThreadPoolExecutor(
                32, 32, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(500),
                new ThreadFactory() {
                    private final AtomicInteger counter = new AtomicInteger(1);
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread thread = new Thread(r, "contexa-vector-worker-" + counter.getAndIncrement());
                        thread.setDaemon(true);
                        return thread;
                    }
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }

    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            ExecutorService vectorOperationExecutor) {
        this(properties, cacheLayer, vectorStore, vectorOperationExecutor, false, PastRecordQuery.unavailable(),
                null, null, null, null);
    }

    /**
     * @param pastRecordQuery the exact past record lookup of the store (W3-18); without one the v20 prompt states that
     *                        its past records were not retrieved
     */
    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            ExecutorService vectorOperationExecutor,
            PastRecordQuery pastRecordQuery) {
        this(properties, cacheLayer, vectorStore, vectorOperationExecutor, false, pastRecordQuery,
                null, null, null, null);
    }

    /**
     * @param retryProperties   the retry of failed stores (BR-C4, QF-8); the defaults, with the retry on, without them
     * @param failedDocumentSink where the documents whose store failed wait; a bounded queue in memory without one
     */
    public UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            ExecutorService vectorOperationExecutor,
            PastRecordQuery pastRecordQuery,
            VectorStoreRetryProperties retryProperties,
            FailedDocumentSink failedDocumentSink) {
        this(properties, cacheLayer, vectorStore, vectorOperationExecutor, false, pastRecordQuery,
                retryProperties, failedDocumentSink, null, null);
    }

    /** The same with the clock and the scheduler of the retry given, so that a test runs it without waiting. */
    UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            ExecutorService vectorOperationExecutor,
            VectorStoreRetryProperties retryProperties,
            FailedDocumentSink failedDocumentSink,
            Clock clock,
            FailedDocumentRetrier.Scheduler retryScheduler) {
        this(properties, cacheLayer, vectorStore, vectorOperationExecutor, false, PastRecordQuery.unavailable(),
                retryProperties, failedDocumentSink, clock, retryScheduler);
    }

    private UnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            ExecutorService vectorOperationExecutor,
            boolean ownsExecutor,
            PastRecordQuery pastRecordQuery,
            VectorStoreRetryProperties retryProperties,
            FailedDocumentSink failedDocumentSink,
            Clock clock,
            FailedDocumentRetrier.Scheduler retryScheduler) {
        this.properties = properties;
        this.cacheLayer = cacheLayer;
        this.vectorStore = vectorStore;
        this.pastRecordQuery = pastRecordQuery != null ? pastRecordQuery : PastRecordQuery.unavailable();
        this.vectorOperationExecutor = vectorOperationExecutor != null ? vectorOperationExecutor : createDefaultExecutor();
        this.ownsExecutor = vectorOperationExecutor == null || ownsExecutor;
        VectorStoreRetryProperties retry = retryProperties != null ? retryProperties : new VectorStoreRetryProperties();
        this.failedStores = retry.isEnabled()
                ? new FailedDocumentRetrier(
                        retry,
                        failedDocumentSink != null ? failedDocumentSink
                                : new InMemoryFailedDocumentSink(retry.getQueueSize()),
                        clock != null ? clock : Clock.systemUTC(),
                        retryScheduler != null ? retryScheduler : FailedDocumentRetrier.threadScheduler(),
                        this::storeAgain,
                        this::deleteDocuments)
                : null;
    }

    @Override
    public void destroy() throws Exception {
        if (failedStores != null) {
            failedStores.shutdown();
        }
        if (ownsExecutor && vectorOperationExecutor != null) {
            vectorOperationExecutor.shutdown();
            try {
                if (!vectorOperationExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    vectorOperationExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                vectorOperationExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public void storeDocument(Document document) {
        validateDocument(document);
        Document stored = withStableId(document);
        enrichStandardMetadata(stored);
        try {
            executeWithBusyRetry(
                    () -> {
                        vectorStore.add(List.of(stored));
                        return null;
                    },
                    properties.getStoreTimeoutMs(),
                    "store document",
                    "Failed to store document");
        } catch (RuntimeException failure) {
            // BR-C4: the document waits for a retry; the caller still sees the failure as before.
            queueForRetry(List.of(stored));
            throw failure;
        }
        cacheLayer.invalidateAfterWrite(List.of(stored));
    }

    /**
     * QF-25 (b): takes the document in for the store retry without a store attempt, for a caller that has no room to
     * store it now (the learning executor is saturated and the caller must not wait for the embedding and the store).
     * The document is the one {@link #storeDocument} would store, under the same id; the retry stores it from its own
     * thread and it is counted as deferred, not as failed. Without the retry (switched off) there is nowhere to leave
     * it, so it is stored at once as {@link #storeDocument} stores it.
     */
    public void storeLater(Document document) {
        if (failedStores == null) {
            storeDocument(document);
            return;
        }
        validateDocument(document);
        Document stored = withStableId(document);
        enrichStandardMetadata(stored);
        failedStores.defer(List.of(stored));
    }

    @Override
    public void storeDocuments(List<Document> requested) {
        if (requested == null || requested.isEmpty()) {
            return;
        }

        List<Document> documents = new ArrayList<>(requested.size());
        for (Document doc : requested) {
            validateDocument(doc);
            Document stored = withStableId(doc);
            enrichStandardMetadata(stored);
            documents.add(stored);
        }

        int batchSize = properties.getBatchSize();
        for (int i = 0; i < documents.size(); i += batchSize) {
            int end = Math.min(i + batchSize, documents.size());
            List<Document> batch = documents.subList(i, end);
            List<Document> immutableBatch = List.copyOf(batch);
            try {
                executeWithBusyRetry(
                        () -> {
                            vectorStore.add(immutableBatch);
                            return null;
                        },
                        properties.getStoreTimeoutMs(),
                        "store document batch",
                        "Failed to store document batch");
            } catch (RuntimeException failure) {
                // BR-C4: the failed batch and the batches after it, which this call no longer reaches, wait for a retry.
                queueForRetry(List.copyOf(documents.subList(i, documents.size())));
                throw failure;
            }
        }

        cacheLayer.invalidateAfterWrite(documents);
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

    /** The exact past record lookup of the store (W3-18). */
    public PastRecordQuery pastRecordQuery() {
        return pastRecordQuery;
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
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            return;
        }

        // BR-C4: a document that waits for a retry must not come back after it was deleted.
        if (failedStores != null) {
            Set<String> ids = new HashSet<>(documentIds);
            failedStores.discard(document -> ids.contains(document.getId()));
        }
        try {
            vectorStore.delete(documentIds);
            cacheLayer.invalidateAfterWrite();
        } catch (Exception e) {
            log.error("[UnifiedVectorService] Failed to delete documents", e);
            throw new VectorStoreException("Failed to delete documents", e);
        }
    }

    /**
     * What became of the stores that failed (BR-C4, QF-8): how many documents failed, wait for a retry now, were stored
     * by a retry and were given up. All zero when the retry is off.
     */
    public StoreFailureStats storeFailureStats() {
        return failedStores != null ? failedStores.stats() : StoreFailureStats.NONE;
    }

    /**
     * Registers a listener of the documents a store retry stored (QF-8b): a record that was stored late, after its
     * original store failed, is told to the listener once the store has it. Without the retry (switched off) nothing is
     * ever retried and the listener is never called.
     */
    public void addRetriedStoreListener(Consumer<List<Document>> listener) {
        if (failedStores != null && listener != null) {
            failedStores.addStoredListener(listener);
        }
    }

    /**
     * Drops the documents of the user that still wait for a store retry, so that a retry does not bring back what the
     * purge of a deleted account removed (BR-C4).
     *
     * @return how many documents were dropped
     */
    public int discardPendingStores(String userId) {
        if (failedStores == null || userId == null || userId.isBlank()) {
            return 0;
        }
        return failedStores.discard(document -> {
            Object owner = document.getMetadata().get(USER_METADATA_KEY);
            return owner != null && userId.equals(owner.toString());
        });
    }

    /** Hands documents whose store failed to the retry; never throws, so the caller still sees the store's failure. */
    private void queueForRetry(List<Document> documents) {
        if (failedStores == null || documents.isEmpty()) {
            return;
        }
        try {
            failedStores.enqueue(documents);
        } catch (RuntimeException queueFailure) {
            log.error("[UnifiedVectorService] {} failed documents could not be queued for a retry", documents.size(),
                    queueFailure);
        }
    }

    /** One try of the retry: stores the documents with the store timeout and a single attempt; throws when it fails. */
    private void storeAgain(List<Document> documents) {
        executeWithinTimeout(
                () -> {
                    vectorStore.add(documents);
                    return null;
                },
                properties.getStoreTimeoutMs(),
                "retry store document batch");
        try {
            cacheLayer.invalidateAfterWrite(documents);
        } catch (RuntimeException invalidationFailure) {
            log.warn("[UnifiedVectorService] The search cache could not be cleared after a retried store: count={}",
                    documents.size(), invalidationFailure);
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

    /**
     * The id an event's record of the document type is stored under (W2-15): storing the event's record again
     * overwrites the row, and the record can be removed by its event (Q-15).
     */
    public static String documentId(String documentType, String eventId) {
        return UUID.nameUUIDFromBytes((documentType + ":" + eventId).getBytes(StandardCharsets.UTF_8)).toString();
    }

    /**
     * The document an event's record is stored as (W2-15): its id comes from the event and the document type, so that
     * storing the same event's record again overwrites the row instead of adding a second one. A document without an
     * event keeps its own id.
     */
    private Document withStableId(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        Object eventId = metadata.get(VectorDocumentMetadata.EVENT_ID);
        Object documentType = metadata.get(VectorDocumentMetadata.DOCUMENT_TYPE);
        if (eventId == null || documentType == null || eventId.toString().isBlank() || documentType.toString().isBlank()) {
            return document;
        }
        String id = documentId(documentType.toString(), eventId.toString());
        if (id.equals(document.getId())) {
            return document;
        }
        return Document.builder()
                .id(id)
                .text(document.getText())
                .metadata(new HashMap<>(metadata))
                .score(document.getScore())
                .build();
    }

    /**
     * BR-S2: where the embedding model the store's vectors are made with is read from ({@code provider/model}), read
     * once at the first store; a document then names it under {@link VectorDocumentMetadata#EMBEDDING_MODEL}. Without
     * one, or when it gives null, no document names a model.
     */
    public void setEmbeddingModelSource(Supplier<String> embeddingModelSource) {
        this.embeddingModelSource = embeddingModelSource;
        this.embeddingModelResolved = false;
    }

    /** BR-S2: the embedding model the stored documents name, null when it is not known. */
    public String embeddingModel() {
        if (!embeddingModelResolved) {
            Supplier<String> source = embeddingModelSource;
            String resolved = null;
            try {
                resolved = source != null ? source.get() : null;
            } catch (RuntimeException e) {
                log.warn("[UnifiedVectorService] The embedding model of the stored documents could not be resolved; "
                        + "documents are stored without it: {}", e.getMessage());
            }
            embeddingModel = resolved != null && !resolved.isBlank() ? resolved.trim() : null;
            embeddingModelResolved = true;
        }
        return embeddingModel;
    }

    private void enrichStandardMetadata(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        // The metadata names the row's own id (W2-15).
        metadata.put("id", document.getId());

        // BR-S2: the embedding model of the vector, kept out of the embedded text of the default formatter.
        String model = embeddingModel();
        if (model != null && !metadata.containsKey(VectorDocumentMetadata.EMBEDDING_MODEL)) {
            metadata.put(VectorDocumentMetadata.EMBEDDING_MODEL, model);
            if (document.getContentFormatter() == Document.DEFAULT_CONTENT_FORMATTER) {
                document.setContentFormatter(EMBEDDING_CONTENT);
            }
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
        // O-1 (3): the limit counts from the embedding call's start; a wait at the model server's gate is left out.
        ModelCallTimer timer = ModelCallTimer.start(effectiveTimeoutMs);
        try {
            SecurityEventTelemetryContext.put("vectorOperationLabel", operationLabel);
            future = vectorOperationExecutor.submit(timer.bind(operation));
            return timer.await(future);
        } catch (TimeoutException timeoutException) {
            if (future != null) {
                future.cancel(true);
            }
            throw new VectorStoreException(
                    String.format(Locale.ROOT, "Vector store %s timed out after %dms", operationLabel, effectiveTimeoutMs),
                    timeoutException);
        } catch (ExecutionException executionException) {
            Throwable cause = executionException.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new VectorStoreException("Vector store " + operationLabel + " failed", cause);
        } catch (InterruptedException interruptedException) {
            if (future != null) {
                future.cancel(true);
            }
            Thread.currentThread().interrupt();
            throw new VectorStoreException("Vector store " + operationLabel + " interrupted", interruptedException);
        }
    }
}
