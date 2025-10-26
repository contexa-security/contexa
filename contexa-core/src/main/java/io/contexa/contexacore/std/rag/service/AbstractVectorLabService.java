package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.dashboard.metrics.vectorstore.VectorStoreMetrics;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Lab 벡터 저장소 서비스 추상 기본 클래스
 * 
 * 템플릿 메서드 패턴을 사용하여 모든 Lab의 벡터 저장 작업을 표준화합니다.
 * Spring AI 표준을 강제하고 공통 기능을 제공합니다.
 * 
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractVectorLabService implements VectorOperations {
    
    protected final StandardVectorStoreService standardVectorStoreService;
    protected final VectorStoreMetrics vectorStoreMetrics;
    
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
    
    /**
     * Lab 이름 반환 (각 Lab에서 구현)
     */
    protected abstract String getLabName();
    
    /**
     * Lab 고유의 문서 타입 반환 (각 Lab에서 구현)
     */
    protected abstract String getDocumentType();
    
    /**
     * Lab별 메타데이터 강화 로직 (각 Lab에서 구현)
     * 
     * @param document 강화할 문서
     * @return 강화된 문서
     */
    protected abstract Document enrichLabSpecificMetadata(Document document);
    
    /**
     * Lab별 문서 검증 로직 (각 Lab에서 구현)
     * 
     * @param document 검증할 문서
     * @throws IllegalArgumentException 검증 실패 시
     */
    protected abstract void validateLabSpecificDocument(Document document);
    
    /**
     * Lab별 후처리 로직 (각 Lab에서 구현, 선택적)
     * 
     * @param document 후처리할 문서
     * @param operationType 작업 타입 (STORE, UPDATE, DELETE)
     */
    protected void postProcessDocument(Document document, OperationType operationType) {
        // 기본 구현은 비어있음, 필요한 Lab에서 오버라이드
    }
    
    /**
     * 템플릿 메서드: 단일 문서 저장
     */
    @Override
    @Transactional
    public void storeDocument(Document document) {
        long startTime = System.currentTimeMillis();
        
        try {
            // 1. 전처리 및 검증
            Document processedDocument = preprocessDocument(document);
            
            // 2. 표준 벡터 저장소에 저장
            standardVectorStoreService.addDocuments(List.of(processedDocument));
            
            // 3. 후처리
            postProcessDocument(processedDocument, OperationType.STORE);
            
            // 4. 메트릭 업데이트
            long duration = System.currentTimeMillis() - startTime;
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.STORE, 1, duration);

            // EventRecorder 인터페이스 호출
            Map<String, Object> eventMetadata = new HashMap<>();
            eventMetadata.put("lab_name", getLabName());
            eventMetadata.put("operation_type", OperationType.STORE.name());
            eventMetadata.put("document_count", 1);
            eventMetadata.put("duration", duration);
            vectorStoreMetrics.recordEvent("vector_store_operation", eventMetadata);
            
            log.debug("[{}] 단일 문서 저장 완료: {}", getLabName(), 
                     processedDocument.getMetadata().get("id"));
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.STORE, e);
            log.error("[{}] 단일 문서 저장 실패", getLabName(), e);
            throw new VectorStoreException("단일 문서 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 템플릿 메서드: 여러 문서 배치 저장
     */
    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            log.warn("[{}] 저장할 문서가 없습니다", getLabName());
            return;
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            // 1. 전처리 및 검증
            List<Document> processedDocuments = new ArrayList<>();
            for (Document doc : documents) {
                processedDocuments.add(preprocessDocument(doc));
            }
            
            // 2. 배치 처리로 저장
            for (int i = 0; i < processedDocuments.size(); i += labBatchSize) {
                int end = Math.min(i + labBatchSize, processedDocuments.size());
                List<Document> batch = processedDocuments.subList(i, end);
                
                standardVectorStoreService.addDocuments(batch);
                
                log.debug("📦 [{}] 배치 저장 완료: {}/{}", getLabName(), end, processedDocuments.size());
            }
            
            // 3. 후처리
            for (Document doc : processedDocuments) {
                postProcessDocument(doc, OperationType.STORE);
            }
            
            // 4. 메트릭 업데이트
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.STORE, 
                                             processedDocuments.size(), 
                                             System.currentTimeMillis() - startTime);
            
            log.info("[{}] 배치 문서 저장 완료: {}개", getLabName(), processedDocuments.size());
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.STORE, e);
            log.error("[{}] 배치 문서 저장 실패", getLabName(), e);
            throw new VectorStoreException("배치 문서 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 비동기 단일 문서 저장
     */
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
    
    /**
     * 비동기 배치 문서 저장
     */
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
    
    /**
     * 유사도 검색 (기본)
     */
    @Override
    public final List<Document> searchSimilar(String query) {
        return searchSimilar(query, Collections.emptyMap());
    }
    
    /**
     * 필터 기반 유사도 검색
     */
    @Override
    public final List<Document> searchSimilar(String query, Map<String, Object> filters) {
        long startTime = System.currentTimeMillis();
        
        try {
            // Lab 고유 필터 추가
            Map<String, Object> labFilters = new HashMap<>(filters);
            labFilters.put("documentType", getDocumentType());
            labFilters.putAll(getLabSpecificFilters());
            
            List<Document> results = standardVectorStoreService.searchWithFilter(query, labFilters);
            
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH, 
                                             results.size(), 
                                             System.currentTimeMillis() - startTime);
            
            log.debug("[{}] 검색 완료: 쿼리='{}', 결과={}개", getLabName(), query, results.size());
            
            return results;
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            log.error("[{}] 검색 실패: 쿼리='{}'", getLabName(), query, e);
            throw new VectorStoreException("검색 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * SearchRequest 기반 고급 검색
     */
    @Override
    public final List<Document> searchSimilar(SearchRequest searchRequest) {
        long startTime = System.currentTimeMillis();
        
        try {
            List<Document> results = standardVectorStoreService.similaritySearch(searchRequest);
            
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH, 
                                             results.size(), 
                                             System.currentTimeMillis() - startTime);
            
            log.debug("[{}] 고급 검색 완료: 결과={}개", getLabName(), results.size());
            
            return results;
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            log.error("[{}] 고급 검색 실패", getLabName(), e);
            throw new VectorStoreException("고급 검색 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 시간 범위 기반 검색
     */
    @Override
    public final List<Document> searchByTimeRange(String query, LocalDateTime startTime, 
                                                 LocalDateTime endTime, String documentType) {
        long start = System.currentTimeMillis();
        
        try {
            String finalDocumentType = documentType != null ? documentType : getDocumentType();
            
            List<Document> results = standardVectorStoreService.searchByTimeRange(
                query, startTime, endTime, finalDocumentType);
            
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.SEARCH, 
                                             results.size(), 
                                             System.currentTimeMillis() - start);
            
            log.debug("[{}] 시간 범위 검색 완료: {}~{}, 결과={}개", 
                     getLabName(), startTime, endTime, results.size());
            
            return results;
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.SEARCH, e);
            log.error("[{}] 시간 범위 검색 실패", getLabName(), e);
            throw new VectorStoreException("시간 범위 검색 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 문서 삭제
     */
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
            
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.DELETE, 
                                             documentIds.size(), 
                                             System.currentTimeMillis() - startTime);
            
            log.info("[{}] 문서 삭제 완료: {}개", getLabName(), documentIds.size());
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.DELETE, e);
            log.error("[{}] 문서 삭제 실패", getLabName(), e);
            throw new VectorStoreException("문서 삭제 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 문서 업데이트
     */
    @Override
    @Transactional
    public void updateDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            log.warn("[{}] 업데이트할 문서가 없습니다", getLabName());
            return;
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            // 1. 전처리 및 검증
            List<Document> processedDocuments = new ArrayList<>();
            for (Document doc : documents) {
                processedDocuments.add(preprocessDocument(doc));
            }
            
            // 2. 표준 벡터 저장소에서 업데이트
            standardVectorStoreService.updateDocuments(processedDocuments);
            
            // 3. 후처리
            for (Document doc : processedDocuments) {
                postProcessDocument(doc, OperationType.UPDATE);
            }
            
            vectorStoreMetrics.recordOperation(getLabName(), OperationType.UPDATE, 
                                             processedDocuments.size(), 
                                             System.currentTimeMillis() - startTime);
            
            log.info("[{}] 문서 업데이트 완료: {}개", getLabName(), processedDocuments.size());
            
        } catch (Exception e) {
            vectorStoreMetrics.recordError(getLabName(), OperationType.UPDATE, e);
            log.error("[{}] 문서 업데이트 실패", getLabName(), e);
            throw new VectorStoreException("문서 업데이트 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 벡터 저장소 통계
     */
    @Override
    public final Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        // 기본 통계
        stats.putAll(standardVectorStoreService.getStatistics());
        
        // Lab별 통계
        stats.putAll(vectorStoreMetrics.getLabStatistics(getLabName()));
        
        return stats;
    }
    
    /**
     * 문서 전처리 (공통 로직 + Lab별 로직)
     */
    private Document preprocessDocument(Document document) {
        try {
            // 1. 기본 검증
            if (document == null) {
                throw new IllegalArgumentException("문서가 null입니다");
            }
            
            if (document.getText() == null || document.getText().trim().isEmpty()) {
                throw new IllegalArgumentException("문서 내용이 비어있습니다");
            }
            
            // 2. 기본 메타데이터 설정
            Map<String, Object> metadata = new HashMap<>(document.getMetadata());
            
            // ID 설정
            if (!metadata.containsKey("id")) {
                metadata.put("id", UUID.randomUUID().toString());
            }
            
            // 타임스탬프 설정
            if (!metadata.containsKey("timestamp")) {
                metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            }
            
            // 문서 타입 설정
            metadata.put("documentType", getDocumentType());
            
            // Lab 정보 설정
            metadata.put("labName", getLabName());
            metadata.put("processingTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            Document processedDocument = new Document(document.getText(), metadata);
            
            // 3. Lab별 검증
            if (validationEnabled) {
                validateLabSpecificDocument(processedDocument);
            }
            
            // 4. Lab별 메타데이터 강화
            if (enrichmentEnabled) {
                processedDocument = enrichLabSpecificMetadata(processedDocument);
            }
            
            return processedDocument;
            
        } catch (Exception e) {
            log.error("[{}] 문서 전처리 실패", getLabName(), e);
            throw new VectorStoreException("문서 전처리 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * Lab별 고유 필터 반환 (각 Lab에서 필요시 오버라이드)
     */
    protected Map<String, Object> getLabSpecificFilters() {
        return Collections.emptyMap();
    }
    
    /**
     * 작업 타입 열거형
     */
    public enum OperationType {
        STORE, SEARCH, UPDATE, DELETE
    }
}