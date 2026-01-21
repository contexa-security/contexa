package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RequiredArgsConstructor
public class UnifiedVectorService implements VectorOperations {

    private final VectorStoreCacheLayer cacheLayer;
    private final StandardVectorStoreService standardService;
    private final BehaviorVectorService behaviorService;
    private final RiskAssessmentVectorService riskService;

    private VectorOperations routeToService(String documentType) {
        if (documentType == null || documentType.isEmpty()) {
                        return standardService;
        }

        return switch (documentType.toLowerCase()) {
            case "behavior_analysis", "behavior", "behavioral_analysis" -> {
                                yield behaviorService;
            }
            case "risk_assessment", "risk", "zero_trust" -> {
                                yield riskService;
            }
            default -> {
                                yield standardService;
            }
        };
    }

    @Override
    @Transactional
    public void storeDocument(Document document) {
        validateDocument(document);
        enrichStandardMetadata(document);

        String documentType = (String) document.getMetadata().get("documentType");
        VectorOperations targetService = routeToService(documentType);

        targetService.storeDocument(document);

        cacheLayer.invalidateAll();
    }

    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            log.warn("[UnifiedVectorService] Attempted to store empty document list");
            return;
        }

        Map<String, List<Document>> documentsByType = new HashMap<>();

        for (Document doc : documents) {
            validateDocument(doc);
            enrichStandardMetadata(doc);

            String documentType = (String) doc.getMetadata().getOrDefault("documentType", "standard");
            documentsByType.computeIfAbsent(documentType, k -> new ArrayList<>()).add(doc);
        }

        for (Map.Entry<String, List<Document>> entry : documentsByType.entrySet()) {
            String documentType = entry.getKey();
            List<Document> docs = entry.getValue();

            VectorOperations targetService = routeToService(documentType);

                        targetService.storeDocuments(docs);
        }

        cacheLayer.invalidateAll();
    }

    @Override
    public CompletableFuture<Void> storeDocumentAsync(Document document) {
        return CompletableFuture.runAsync(() -> storeDocument(document));
    }

    @Override
    public CompletableFuture<Void> storeDocumentsAsync(List<Document> documents) {
        return CompletableFuture.runAsync(() -> storeDocuments(documents));
    }

    @Override
    public List<Document> searchSimilar(String query) {
        return searchSimilar(SearchRequest.builder()
            .query(query)
            .topK(10)
            .similarityThreshold(0.0)  
            .build());
    }

    @Override
    public List<Document> searchSimilar(String query, Map<String, Object> filters) {
        
        String documentType = filters != null ? (String) filters.get("documentType") : null;

        if (documentType != null) {
            VectorOperations targetService = routeToService(documentType);
            return targetService.searchSimilar(query, filters);
        }

        return standardService.searchSimilar(query, filters != null ? filters : Map.of());
    }

    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        
        try {
            
            List<Document> cachedResults = cacheLayer.similaritySearch(searchRequest);

            if (cachedResults != null && !cachedResults.isEmpty()) {
                                return cachedResults;
            }

                        List<Document> results = standardService.similaritySearch(searchRequest);

                        return results;

        } catch (Exception e) {
            log.error("[UnifiedVectorService] Error during similarity search", e);
            throw new VectorStoreException("Similarity search failed", e);
        }
    }

    @Override
    public List<Document> searchByTimeRange(String query, LocalDateTime startTime,
                                           LocalDateTime endTime, String documentType) {
        
        VectorOperations targetService = routeToService(documentType);
        return targetService.searchByTimeRange(query, startTime, endTime, documentType);
    }

    @Override
    @Transactional
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            log.warn("[UnifiedVectorService] Attempted to delete empty document ID list");
            return;
        }

        try {
            standardService.deleteDocuments(documentIds);
        } catch (Exception e) {
            log.warn("[UnifiedVectorService] Failed to delete from StandardVectorStoreService", e);
        }

        cacheLayer.invalidateAll();
    }

    @Override
    @Transactional
    public void updateDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            log.warn("[UnifiedVectorService] Attempted to update empty document list");
            return;
        }

        Map<String, List<Document>> documentsByType = new HashMap<>();

        for (Document doc : documents) {
            validateDocument(doc);
            String documentType = (String) doc.getMetadata().getOrDefault("documentType", "standard");
            documentsByType.computeIfAbsent(documentType, k -> new ArrayList<>()).add(doc);
        }

        for (Map.Entry<String, List<Document>> entry : documentsByType.entrySet()) {
            String documentType = entry.getKey();
            List<Document> docs = entry.getValue();

            VectorOperations targetService = routeToService(documentType);
            targetService.updateDocuments(docs);
        }

        cacheLayer.invalidateAll();
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        Map<String, Object> standardStats = standardService.getStatistics();
        stats.put("standard", standardStats);

        VectorStoreCacheLayer.CacheStatistics cacheStats = cacheLayer.getStatistics();
        stats.put("cache", Map.of(
            "hitRate", cacheStats.getHitRate(),
            "missRate", cacheStats.getMissRate(),
            "size", cacheStats.getEstimatedSize(),
            "evictions", cacheStats.getEvictionCount()
        ));

        stats.put("behavior", behaviorService.getStatistics());
        stats.put("riskAssessment", riskService.getStatistics());

                return stats;
    }

    private void validateDocument(Document document) {
        if (document == null) {
            throw new VectorStoreException("Document cannot be null");
        }

        if (document.getText() == null || document.getText().isEmpty()) {
            throw new VectorStoreException("Document text cannot be empty");
        }

        Map<String, Object> metadata = document.getMetadata();
        if (metadata == null) {
            throw new VectorStoreException("Document metadata cannot be null");
        }

    }

    private void enrichStandardMetadata(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("id")) {
            metadata.put("id", UUID.randomUUID().toString());
        }

        if (!metadata.containsKey("timestamp")) {
            metadata.put("timestamp", LocalDateTime.now().toString());
        }

        if (!metadata.containsKey("documentType")) {
            metadata.put("documentType", "standard");
        }

        if (!metadata.containsKey("version")) {
            metadata.put("version", "1.0");
        }
    }
}
