package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;


@Slf4j
public abstract class AbstractVectorLabService implements VectorOperations {

    protected final StandardVectorStoreService standardVectorStoreService;
    protected final VectorStoreMetrics vectorStoreMetrics;

    
    protected AbstractVectorLabService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        this.standardVectorStoreService = standardVectorStoreService;
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
    
    private Executor asyncExecutor;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    @PostConstruct
    protected void initialize() {
        this.asyncExecutor = Executors.newFixedThreadPool(4);
        log.info("{} 초기화 완료 - 배치크기: {}, 비동기: {}, 검증: {}, 강화: {}", 
                getLabName(), labBatchSize, asyncEnabled, validationEnabled, enrichmentEnabled);
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
            
            
            standardVectorStoreService.addDocuments(List.of(processedDocument));
            
            
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

            log.debug("[{}] 단일 문서 저장 완료: {}", getLabName(),
                     processedDocument.getMetadata().get("id"));

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.STORE, e);
            }
            log.error("[{}] 단일 문서 저장 실패", getLabName(), e);
            throw new VectorStoreException("단일 문서 저장 실패: " + e.getMessage(), e);
        }
    }
    
    
    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            log.warn("[{}] 저장할 문서가 없습니다", getLabName());
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
                
                standardVectorStoreService.addDocuments(batch);
                
                log.debug("[{}] 배치 저장 완료: {}/{}", getLabName(), end, processedDocuments.size());
            }
            
            
            for (Document doc : processedDocuments) {
                postProcessDocument(doc, OperationType.STORE);
            }
            
            
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.STORE,
                                                 processedDocuments.size(),
                                                 System.currentTimeMillis() - startTime);
            }

            log.info("[{}] 배치 문서 저장 완료: {}개", getLabName(), processedDocuments.size());

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.STORE, e);
            }
            log.error("[{}] 배치 문서 저장 실패", getLabName(), e);
            throw new VectorStoreException("배치 문서 저장 실패: " + e.getMessage(), e);
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
                    log.error("[{}] 비동기 단일 문서 저장 실패", getLabName(), throwable);
                    throw new VectorStoreException("비동기 단일 문서 저장 실패", throwable);
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
                    log.error("[{}] 비동기 배치 문서 저장 실패", getLabName(), throwable);
                    throw new VectorStoreException("비동기 배치 문서 저장 실패", throwable);
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
            
            List<Document> results = standardVectorStoreService.searchWithFilter(query, labFilters);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH,
                                                 results.size(),
                                                 System.currentTimeMillis() - startTime);
            }

            log.debug("[{}] 검색 완료: 쿼리='{}', 결과={}개", getLabName(), query, results.size());

            return results;

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            }
            log.error("[{}] 검색 실패: 쿼리='{}'", getLabName(), query, e);
            throw new VectorStoreException("검색 실패: " + e.getMessage(), e);
        }
    }
    
    
    @Override
    public final List<Document> searchSimilar(SearchRequest searchRequest) {
        long startTime = System.currentTimeMillis();
        
        try {
            List<Document> results = standardVectorStoreService.similaritySearch(searchRequest);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH,
                                                 results.size(),
                                                 System.currentTimeMillis() - startTime);
            }

            log.debug("[{}] 고급 검색 완료: 결과={}개", getLabName(), results.size());

            return results;

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            }
            log.error("[{}] 고급 검색 실패", getLabName(), e);
            throw new VectorStoreException("고급 검색 실패: " + e.getMessage(), e);
        }
    }
    
    
    @Override
    public final List<Document> searchByTimeRange(String query, LocalDateTime startTime, 
                                                 LocalDateTime endTime, String documentType) {
        long start = System.currentTimeMillis();
        
        try {
            String finalDocumentType = documentType != null ? documentType : getDocumentType();
            
            List<Document> results = standardVectorStoreService.searchByTimeRange(
                query, startTime, endTime, finalDocumentType);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH,
                                                 results.size(),
                                                 System.currentTimeMillis() - start);
            }

            log.debug("[{}] 시간 범위 검색 완료: {}~{}, 결과={}개",
                     getLabName(), startTime, endTime, results.size());

            return results;

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            }
            log.error("[{}] 시간 범위 검색 실패", getLabName(), e);
            throw new VectorStoreException("시간 범위 검색 실패: " + e.getMessage(), e);
        }
    }
    
    
    @Override
    @Transactional
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            log.warn("[{}] 삭제할 문서 ID가 없습니다", getLabName());
            return;
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            standardVectorStoreService.deleteDocuments(documentIds);

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.DELETE,
                                                 documentIds.size(),
                                                 System.currentTimeMillis() - startTime);
            }

            log.info("[{}] 문서 삭제 완료: {}개", getLabName(), documentIds.size());

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.DELETE, e);
            }
            log.error("[{}] 문서 삭제 실패", getLabName(), e);
            throw new VectorStoreException("문서 삭제 실패: " + e.getMessage(), e);
        }
    }
    
    
    @Override
    @Transactional
    public void updateDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            log.warn("[{}] 업데이트할 문서가 없습니다", getLabName());
            return;
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            
            List<Document> processedDocuments = new ArrayList<>();
            for (Document doc : documents) {
                processedDocuments.add(preprocessDocument(doc));
            }
            
            
            standardVectorStoreService.updateDocuments(processedDocuments);
            
            
            for (Document doc : processedDocuments) {
                postProcessDocument(doc, OperationType.UPDATE);
            }

            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordOperation(getLabName(), OperationType.UPDATE,
                                                 processedDocuments.size(),
                                                 System.currentTimeMillis() - startTime);
            }

            log.info("[{}] 문서 업데이트 완료: {}개", getLabName(), processedDocuments.size());

        } catch (Exception e) {
            if (vectorStoreMetrics != null) {
                vectorStoreMetrics.recordError(getLabName(), OperationType.UPDATE, e);
            }
            log.error("[{}] 문서 업데이트 실패", getLabName(), e);
            throw new VectorStoreException("문서 업데이트 실패: " + e.getMessage(), e);
        }
    }
    
    
    @Override
    public final Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        
        stats.putAll(standardVectorStoreService.getStatistics());

        
        if (vectorStoreMetrics != null) {
            stats.putAll(vectorStoreMetrics.getLabStatistics(getLabName()));
        }

        return stats;
    }
    
    
    private Document preprocessDocument(Document document) {
        try {
            
            if (document == null) {
                throw new IllegalArgumentException("문서가 null입니다");
            }
            
            if (document.getText() == null || document.getText().trim().isEmpty()) {
                throw new IllegalArgumentException("문서 내용이 비어있습니다");
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
            log.error("[{}] 문서 전처리 실패", getLabName(), e);
            throw new VectorStoreException("문서 전처리 실패: " + e.getMessage(), e);
        }
    }
    
    
    protected Map<String, Object> getLabSpecificFilters() {
        return Collections.emptyMap();
    }
    
    
    public enum OperationType {
        STORE, SEARCH, UPDATE, DELETE
    }
}