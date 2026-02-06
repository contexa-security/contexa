package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.std.rag.service.VectorOperations.VectorStoreException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

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
        vectorStore.add(List.of(document));
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
            vectorStore.add(batch);
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

        return searchSimilar(builder.build());
    }

    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        try {
            List<Document> cachedResults = cacheLayer.similaritySearch(searchRequest);

            if (cachedResults != null && !cachedResults.isEmpty()) {
                return cachedResults;
            }

            return vectorStore.similaritySearch(searchRequest);

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
        } catch (Exception e) {
            log.error("[UnifiedVectorService] Failed to delete documents", e);
        }

        cacheLayer.invalidateAll();
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
            metadata.put("documentType", "standard");
        }

        if (!metadata.containsKey("version")) {
            metadata.put("version", "1.0");
        }
    }
}
