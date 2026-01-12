package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.document.DocumentTransformer;
import org.springframework.ai.reader.TextReader;
import org.springframework.ai.transformer.splitter.TokenTextSplitter;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Spring AI 표준 VectorStore 서비스
 * 
 * Spring AI 공식 표준 API를 100% 준수하여 구현된 벡터 저장소 서비스입니다.
 * PgVectorStore를 활용하여 문서 임베딩, 저장, 검색 기능을 제공합니다.
 * 
 * @since 1.0.0
 */
@RequiredArgsConstructor
public class StandardVectorStoreService implements VectorOperations {

    // PgVectorStoreProperties로 통합된 설정
    private final PgVectorStoreProperties properties;

    private final VectorStore vectorStore;
    private final EmbeddingModel embeddingModel;
    private final JdbcTemplate jdbcTemplate;
    private ExecutorService executorService;
    
    // 문서 변환기
    private TokenTextSplitter textSplitter;
    private DocumentTransformer keywordEnricher;
    private DocumentTransformer summaryEnricher;
    
    // 메트릭 추적
    private final Map<String, Long> metrics = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initialize() {

        executorService = Executors.newFixedThreadPool(properties.getParallelThreads());
        // 문서 분할기 초기화
        this.textSplitter = new TokenTextSplitter(
            properties.getDocument().getChunkSize(),
            properties.getDocument().getChunkOverlap(),
            5,
            10000,
            true
        );

        // 메타데이터 강화기 초기화 (커스텀 구현)
        this.keywordEnricher = new KeywordDocumentTransformer();
        this.summaryEnricher = new SummaryDocumentTransformer(embeddingModel);

        // PgVector 인덱스 최적화
        optimizePgVectorIndex();
    }
    
    /**
     * 단일 문서 저장 (VectorOperations 인터페이스 구현)
     */
    @Override
    @Transactional
    public void storeDocument(Document document) {
        addDocuments(List.of(document));
    }

    /**
     * 여러 문서 저장 (VectorOperations 인터페이스 구현)
     */
    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        addDocuments(documents);
    }

    /**
     * 비동기 단일 문서 저장 (VectorOperations 인터페이스 구현)
     */
    @Override
    public CompletableFuture<Void> storeDocumentAsync(Document document) {
        return CompletableFuture.runAsync(() -> storeDocument(document), executorService);
    }

    /**
     * 비동기 여러 문서 저장 (VectorOperations 인터페이스 구현)
     */
    @Override
    public CompletableFuture<Void> storeDocumentsAsync(List<Document> documents) {
        return CompletableFuture.runAsync(() -> storeDocuments(documents), executorService);
    }

    /**
     * 문서 저장 (Spring AI 표준 API)
     *
     * 문서를 청크로 분할하고, 임베딩을 생성한 후 벡터 저장소에 저장합니다.
     */
    @Transactional
    public void addDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        
        long startTime = System.currentTimeMillis();
        
        // 1. 문서 전처리 및 분할
        List<Document> processedDocuments = preprocessDocuments(documents);
        
        // 2. 메타데이터 강화
        processedDocuments = enrichDocumentMetadata(processedDocuments);
        
        // 3. 배치 처리로 벡터 저장소에 추가
        processBatchDocuments(processedDocuments);
        
        // 메트릭 업데이트
        long duration = System.currentTimeMillis() - startTime;
        metrics.put("lastAddDuration", duration);
        metrics.put("totalDocumentsAdded", 
            metrics.getOrDefault("totalDocumentsAdded", 0L) + documents.size());
    }
    
    /**
     * 유사도 검색 (VectorOperations 인터페이스 구현)
     */
    @Override
    public List<Document> searchSimilar(String query) {
        return similaritySearch(query);
    }

    /**
     * 필터 기반 유사도 검색 (VectorOperations 인터페이스 구현)
     */
    @Override
    public List<Document> searchSimilar(String query, Map<String, Object> filters) {
        return searchWithFilter(query, filters);
    }

    /**
     * SearchRequest 기반 유사도 검색 (VectorOperations 인터페이스 구현)
     */
    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        return similaritySearch(searchRequest);
    }

    /**
     * 문서 검색 (Spring AI 표준 API)
     *
     * 쿼리에 대한 유사도 검색을 수행하고 관련 문서를 반환합니다.
     */
    public List<Document> similaritySearch(String query) {
        return similaritySearch(SearchRequest.builder()
            .query(query)
            .build());
    }
    
    /**
     * 고급 문서 검색 (Spring AI 표준 API)
     *
     * SearchRequest를 사용하여 필터, 유사도 임계값, topK 등을 지정할 수 있습니다.
     *
     * AI Native v6.3: Spring AI Document.getScore()를 metadata에 추가
     * - Spring AI PgVectorStore는 Document.getScore()로 similarity score 제공
     * - 프롬프트 구성에서 "similarityScore" 키로 접근하므로 metadata에 복사
     */
    public List<Document> similaritySearch(SearchRequest searchRequest) {
        long startTime = System.currentTimeMillis();

        // VectorStore의 표준 검색 API 사용
        List<Document> results = vectorStore.similaritySearch(searchRequest);

        // AI Native v6.3: Document.getScore()를 metadata에 추가
        // Spring AI는 score를 Document 객체의 score 필드로 반환
        // 프롬프트 구성 코드에서 metadata.get("similarityScore")로 접근하므로 복사 필요
        for (Document doc : results) {
            Double score = doc.getScore();
            if (score != null) {
                doc.getMetadata().put("similarityScore", score);
                doc.getMetadata().put("score", score);  // 호환성을 위한 추가 키
            }
        }

        // 메트릭 업데이트
        long duration = System.currentTimeMillis() - startTime;
        metrics.put("lastSearchDuration", duration);
        metrics.put("totalSearches",
            metrics.getOrDefault("totalSearches", 0L) + 1);

        return results;
    }
    
    /**
     * 필터를 사용한 검색
     * 
     * Spring AI FilterExpressionBuilder를 사용하여 메타데이터 기반 필터링을 수행합니다.
     */
    public List<Document> searchWithFilter(String query, Map<String, Object> filterCriteria) {
        FilterExpressionBuilder builder = new FilterExpressionBuilder();
        Filter.Expression filter = buildFilterExpression(builder, filterCriteria);

        // AI Native v4.2.0: topK를 filterCriteria에서 가져오거나 설정값 사용
        int topK = filterCriteria.containsKey("topK")
            ? ((Number) filterCriteria.get("topK")).intValue()
            : properties.getTopK();

        SearchRequest searchRequest = SearchRequest.builder()
            .query(query)
            .topK(topK)
            .similarityThreshold(properties.getSimilarityThreshold())
            .filterExpression(filter)
            .build();

        return similaritySearch(searchRequest);
    }
    
    /**
     * 시간 범위 기반 검색
     */
    public List<Document> searchByTimeRange(
            String query, 
            LocalDateTime startTime, 
            LocalDateTime endTime,
            String documentType) {
        
        FilterExpressionBuilder builder = new FilterExpressionBuilder();

        // AI Native v4.2.0: 시간 필터 Op 생성 (재사용 가능)
        FilterExpressionBuilder.Op timeFilterOp = builder.and(
            builder.gte("timestamp", startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)),
            builder.lte("timestamp", endTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
        );

        // 문서 타입 필터 추가 - 기존 timeFilterOp 재사용
        Filter.Expression timeFilter;
        if (documentType != null && !documentType.isEmpty()) {
            timeFilter = builder.and(timeFilterOp, builder.eq("documentType", documentType)).build();
        } else {
            timeFilter = timeFilterOp.build();
        }
        
        // AI Native v4.2.0: topK 설정값 사용
        SearchRequest searchRequest = SearchRequest.builder()
            .query(query)
            .topK(properties.getTopK())
            .similarityThreshold(properties.getSimilarityThreshold())
            .filterExpression(timeFilter)
            .build();
        
        return similaritySearch(searchRequest);
    }
    
    /**
     * 문서 삭제
     */
    @Transactional
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            return;
        }
        
        // VectorStore의 표준 삭제 API 사용
        vectorStore.delete(documentIds);
        
        metrics.put("totalDocumentsDeleted", 
            metrics.getOrDefault("totalDocumentsDeleted", 0L) + documentIds.size());
    }
    
    /**
     * 문서 업데이트 (삭제 후 재추가)
     */
    @Transactional
    public void updateDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        
        // 기존 문서 ID 추출
        List<String> documentIds = documents.stream()
            .map(doc -> (String) doc.getMetadata().get("id"))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
        
        // 기존 문서 삭제
        if (!documentIds.isEmpty()) {
            deleteDocuments(documentIds);
        }
        
        // 새 문서 추가
        addDocuments(documents);
    }
    
    /**
     * 문서 전처리
     */
    private List<Document> preprocessDocuments(List<Document> documents) {
        List<Document> allChunks = new ArrayList<>();
        
        for (Document doc : documents) {
            // 문서 ID 생성
            ensureDocumentId(doc);
            
            // 타임스탬프 추가
            ensureTimestamp(doc);
            
            // 문서 분할
            List<Document> chunks = textSplitter.apply(List.of(doc));
            
            // 각 청크에 원본 문서 메타데이터 복사
            for (Document chunk : chunks) {
                chunk.getMetadata().putAll(doc.getMetadata());
                chunk.getMetadata().put("chunkId", UUID.randomUUID().toString());
                chunk.getMetadata().put("originalDocumentId", doc.getMetadata().get("id"));
            }
            
            allChunks.addAll(chunks);
        }
        
        return allChunks;
    }
    
    /**
     * 메타데이터 강화 (AI Native v4.2.0 - 예외 처리 추가)
     */
    private List<Document> enrichDocumentMetadata(List<Document> documents) {
        // 키워드 추출
        documents = keywordEnricher.apply(documents);

        // 요약 생성 (비동기 처리, 개별 문서 실패 시 원본 반환)
        List<CompletableFuture<Document>> futures = documents.stream()
            .map(doc -> CompletableFuture.supplyAsync(() -> {
                List<Document> enriched = summaryEnricher.apply(List.of(doc));
                return enriched.isEmpty() ? doc : enriched.get(0);
            }, executorService)
            // AI Native v4.2.0: 개별 문서 강화 실패 시 원본 문서 반환 (전체 실패 방지)
            .exceptionally(ex -> doc))
            .collect(Collectors.toList());

        return futures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
    }
    
    /**
     * 배치 문서 처리
     */
    private void processBatchDocuments(List<Document> documents) {
        // 배치로 나누어 처리
        int batchSize = properties.getBatchSize();
        for (int i = 0; i < documents.size(); i += batchSize) {
            int end = Math.min(i + batchSize, documents.size());
            List<Document> batch = documents.subList(i, end);

            // 벡터 저장소에 추가
            vectorStore.add(batch);
        }
    }
    
    /**
     * 필터 표현식 생성 (AI Native v4.2.0 - 다중 조건 AND 결합 구현)
     *
     * 여러 필터 조건을 AND로 결합하여 정확한 검색 수행
     * 예: {"documentType": "behavior", "userId": "john"} → documentType='behavior' AND userId='john'
     *
     * 참고: FilterExpressionBuilder API
     * - builder.eq(), gte(), lte() 등은 Op 반환
     * - builder.and(Op, Op)는 Ops 반환
     * - .build()는 최종 Expression 반환
     * - 이미 .build()된 Expression은 and()에 다시 넣을 수 없음
     */
    @SuppressWarnings("unchecked")
    private Filter.Expression buildFilterExpression(
            FilterExpressionBuilder builder,
            Map<String, Object> criteria) {

        // Op 목록을 수집 (Expression이 아닌 Op)
        List<FilterExpressionBuilder.Op> ops = new ArrayList<>();

        for (Map.Entry<String, Object> entry : criteria.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // topK는 필터가 아니므로 skip
            if ("topK".equals(key)) {
                continue;
            }

            if (value instanceof String) {
                ops.add(builder.eq(key, value));
            } else if (value instanceof Number) {
                ops.add(builder.eq(key, value));
            } else if (value instanceof List) {
                ops.add(builder.in(key, (List<?>) value));
            } else if (value instanceof Map) {
                // 범위 쿼리 처리
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

        // AI Native v4.2.0: 다중 조건 AND 결합 구현
        if (ops.size() == 1) {
            return ops.get(0).build();
        }

        // 여러 조건을 AND로 결합 (Op 단계에서 결합 후 최종 build)
        FilterExpressionBuilder.Op combined = ops.get(0);
        for (int i = 1; i < ops.size(); i++) {
            combined = builder.and(combined, ops.get(i));
        }
        return combined.build();
    }
    
    /**
     * PgVector 인덱스 최적화
     */
    private void optimizePgVectorIndex() {
        try {
            // HNSW 인덱스 파라미터 최적화
            if (PgVectorStoreProperties.IndexType.HNSW == properties.getIndexType()) {
                String sql = String.format("""
                    CREATE INDEX IF NOT EXISTS embedding_hnsw_idx
                    ON vector_store USING hnsw (embedding vector_cosine_ops)
                    WITH (m = %d, ef_construction = %d);
                    """,
                    properties.getHnsw().getM(),
                    properties.getHnsw().getEfConstruction()
                );
                jdbcTemplate.execute(sql);

                // 검색 성능 최적화
                jdbcTemplate.execute(String.format("SET hnsw.ef_search = %d;",
                    properties.getHnsw().getEfSearch()));
            }
            
            // 통계 업데이트
            jdbcTemplate.execute("ANALYZE vector_store;");
            
        } catch (Exception e) {
            // 인덱스가 이미 존재하거나 권한이 없는 경우 무시
            // 프로덕션 환경에서는 DBA가 관리
        }
    }
    
    /**
     * 문서 ID 확인 및 생성
     */
    private void ensureDocumentId(Document document) {
        if (!document.getMetadata().containsKey("id")) {
            document.getMetadata().put("id", UUID.randomUUID().toString());
        }
    }
    
    /**
     * 타임스탬프 확인 및 추가
     */
    private void ensureTimestamp(Document document) {
        if (!document.getMetadata().containsKey("timestamp")) {
            document.getMetadata().put("timestamp", 
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        }
    }
    
    /**
     * PDF 문서 읽기 (Spring AI 표준)
     * 
     * 주의: Spring AI 1.0.0-SNAPSHOT에서 PDF Reader API가 변경되었습니다.
     * 실제 구현 시 최신 API를 확인하세요.
     */
    public List<Document> readPdfDocument(Resource pdfResource) {
        // PDF 문서 읽기는 Spring AI의 최신 API를 사용해야 합니다
        // 예시: 텍스트 리더로 대체
        TextReader reader = new TextReader(pdfResource);
        return reader.get();
    }
    
    /**
     * 텍스트 문서 읽기 (Spring AI 표준)
     */
    public List<Document> readTextDocument(Resource textResource) {
        TextReader reader = new TextReader(textResource);
        return reader.get();
    }
    
    /**
     * 벡터 저장소 통계
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        // 메트릭 복사
        stats.putAll(metrics);
        
        // 현재 문서 수 조회
        try {
            Long documentCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM vector_store",
                Long.class
            );
            stats.put("totalDocuments", documentCount);
            
            // AI Native v4.2.0: 인덱스 크기 버그 수정 - 문자열 또는 바이트 값 저장
            String indexSizeStr = jdbcTemplate.queryForObject(
                "SELECT pg_size_pretty(pg_relation_size('embedding_hnsw_idx'))::text",
                String.class
            );
            stats.put("indexSize", indexSizeStr != null ? indexSizeStr : "0 bytes");
            
        } catch (Exception e) {
            // 통계 조회 실패는 무시
        }
        
        return stats;
    }
    
    /**
     * 리소스 정리
     */
    public void shutdown() {
        executorService.shutdown();
    }
    
    /**
     * 키워드 추출 변환기 (커스텀 구현)
     */
    private static class KeywordDocumentTransformer implements DocumentTransformer {
        private static final int MAX_KEYWORDS = 5;
        
        @Override
        public List<Document> apply(List<Document> documents) {
            for (Document doc : documents) {
                String content = doc.getText();
                if (content != null && !content.isEmpty()) {
                    // 간단한 키워드 추출 (실제로는 더 복잡한 알고리즘 사용)
                    Set<String> keywords = extractKeywords(content);
                    doc.getMetadata().put("keywords", new ArrayList<>(keywords));
                }
            }
            return documents;
        }
        
        private Set<String> extractKeywords(String content) {
            // 간단한 키워드 추출 로직
            String[] words = content.toLowerCase().split("\\s+");
            Map<String, Integer> wordFreq = new HashMap<>();
            
            for (String word : words) {
                if (word.length() > 3 && !isStopWord(word)) {
                    wordFreq.merge(word, 1, Integer::sum);
                }
            }
            
            return wordFreq.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(MAX_KEYWORDS)
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
        }
        
        private boolean isStopWord(String word) {
            Set<String> stopWords = Set.of("the", "and", "for", "with", "this", "that", "from", "have", "been");
            return stopWords.contains(word);
        }
    }
    
    /**
     * 요약 생성 변환기 (커스텀 구현)
     */
    private static class SummaryDocumentTransformer implements DocumentTransformer {
        private final EmbeddingModel embeddingModel;
        
        public SummaryDocumentTransformer(EmbeddingModel embeddingModel) {
            this.embeddingModel = embeddingModel;
        }
        
        @Override
        public List<Document> apply(List<Document> documents) {
            for (Document doc : documents) {
                String content = doc.getText();
                if (content != null && content.length() > 100) {
                    // 간단한 요약 생성 (처음 200자 사용)
                    String summary = content.length() > 200 
                        ? content.substring(0, 200) + "..."
                        : content;
                    doc.getMetadata().put("summary", summary);
                }
            }
            return documents;
        }
    }
}