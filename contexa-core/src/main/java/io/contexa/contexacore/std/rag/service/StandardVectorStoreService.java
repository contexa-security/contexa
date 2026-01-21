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

@RequiredArgsConstructor
public class StandardVectorStoreService implements VectorOperations {

    private final PgVectorStoreProperties properties;

    private final VectorStore vectorStore;
    private final EmbeddingModel embeddingModel;
    private final JdbcTemplate jdbcTemplate;
    private ExecutorService executorService;

    private TokenTextSplitter textSplitter;
    private DocumentTransformer keywordEnricher;
    private DocumentTransformer summaryEnricher;

    private final Map<String, Long> metrics = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initialize() {

        executorService = Executors.newFixedThreadPool(properties.getParallelThreads());
        
        this.textSplitter = new TokenTextSplitter(
            properties.getDocument().getChunkSize(),
            properties.getDocument().getChunkOverlap(),
            5,
            10000,
            true
        );

        this.keywordEnricher = new KeywordDocumentTransformer();
        this.summaryEnricher = new SummaryDocumentTransformer(embeddingModel);

        optimizePgVectorIndex();
    }

    @Override
    @Transactional
    public void storeDocument(Document document) {
        addDocuments(List.of(document));
    }

    @Override
    @Transactional
    public void storeDocuments(List<Document> documents) {
        addDocuments(documents);
    }

    @Override
    public CompletableFuture<Void> storeDocumentAsync(Document document) {
        return CompletableFuture.runAsync(() -> storeDocument(document), executorService);
    }

    @Override
    public CompletableFuture<Void> storeDocumentsAsync(List<Document> documents) {
        return CompletableFuture.runAsync(() -> storeDocuments(documents), executorService);
    }

    @Transactional
    public void addDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        
        long startTime = System.currentTimeMillis();

        List<Document> processedDocuments = preprocessDocuments(documents);

        processedDocuments = enrichDocumentMetadata(processedDocuments);

        processBatchDocuments(processedDocuments);

        long duration = System.currentTimeMillis() - startTime;
        metrics.put("lastAddDuration", duration);
        metrics.put("totalDocumentsAdded", 
            metrics.getOrDefault("totalDocumentsAdded", 0L) + documents.size());
    }

    @Override
    public List<Document> searchSimilar(String query) {
        return similaritySearch(query);
    }

    @Override
    public List<Document> searchSimilar(String query, Map<String, Object> filters) {
        return searchWithFilter(query, filters);
    }

    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        return similaritySearch(searchRequest);
    }

    public List<Document> similaritySearch(String query) {
        return similaritySearch(SearchRequest.builder()
            .query(query)
            .build());
    }

    public List<Document> similaritySearch(SearchRequest searchRequest) {
        long startTime = System.currentTimeMillis();

        List<Document> results = vectorStore.similaritySearch(searchRequest);

        for (Document doc : results) {
            Double score = doc.getScore();
            if (score != null) {
                doc.getMetadata().put("similarityScore", score);
                doc.getMetadata().put("score", score);  
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        metrics.put("lastSearchDuration", duration);
        metrics.put("totalSearches",
            metrics.getOrDefault("totalSearches", 0L) + 1);

        return results;
    }

    public List<Document> searchWithFilter(String query, Map<String, Object> filterCriteria) {
        FilterExpressionBuilder builder = new FilterExpressionBuilder();
        Filter.Expression filter = buildFilterExpression(builder, filterCriteria);

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

    public List<Document> searchByTimeRange(
            String query, 
            LocalDateTime startTime, 
            LocalDateTime endTime,
            String documentType) {
        
        FilterExpressionBuilder builder = new FilterExpressionBuilder();

        FilterExpressionBuilder.Op timeFilterOp = builder.and(
            builder.gte("timestamp", startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)),
            builder.lte("timestamp", endTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
        );

        Filter.Expression timeFilter;
        if (documentType != null && !documentType.isEmpty()) {
            timeFilter = builder.and(timeFilterOp, builder.eq("documentType", documentType)).build();
        } else {
            timeFilter = timeFilterOp.build();
        }

        SearchRequest searchRequest = SearchRequest.builder()
            .query(query)
            .topK(properties.getTopK())
            .similarityThreshold(properties.getSimilarityThreshold())
            .filterExpression(timeFilter)
            .build();
        
        return similaritySearch(searchRequest);
    }

    @Transactional
    public void deleteDocuments(List<String> documentIds) {
        if (documentIds == null || documentIds.isEmpty()) {
            return;
        }

        vectorStore.delete(documentIds);
        
        metrics.put("totalDocumentsDeleted", 
            metrics.getOrDefault("totalDocumentsDeleted", 0L) + documentIds.size());
    }

    @Transactional
    public void updateDocuments(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }

        List<String> documentIds = documents.stream()
            .map(doc -> (String) doc.getMetadata().get("id"))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());

        if (!documentIds.isEmpty()) {
            deleteDocuments(documentIds);
        }

        addDocuments(documents);
    }

    private List<Document> preprocessDocuments(List<Document> documents) {
        List<Document> allChunks = new ArrayList<>();
        
        for (Document doc : documents) {
            
            ensureDocumentId(doc);

            ensureTimestamp(doc);

            List<Document> chunks = textSplitter.apply(List.of(doc));

            for (Document chunk : chunks) {
                chunk.getMetadata().putAll(doc.getMetadata());
                chunk.getMetadata().put("chunkId", UUID.randomUUID().toString());
                chunk.getMetadata().put("originalDocumentId", doc.getMetadata().get("id"));
            }
            
            allChunks.addAll(chunks);
        }
        
        return allChunks;
    }

    private List<Document> enrichDocumentMetadata(List<Document> documents) {
        
        documents = keywordEnricher.apply(documents);

        List<CompletableFuture<Document>> futures = documents.stream()
            .map(doc -> CompletableFuture.supplyAsync(() -> {
                List<Document> enriched = summaryEnricher.apply(List.of(doc));
                return enriched.isEmpty() ? doc : enriched.get(0);
            }, executorService)
            
            .exceptionally(ex -> doc))
            .collect(Collectors.toList());

        return futures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
    }

    private void processBatchDocuments(List<Document> documents) {
        
        int batchSize = properties.getBatchSize();
        for (int i = 0; i < documents.size(); i += batchSize) {
            int end = Math.min(i + batchSize, documents.size());
            List<Document> batch = documents.subList(i, end);

            vectorStore.add(batch);
        }
    }

    @SuppressWarnings("unchecked")
    private Filter.Expression buildFilterExpression(
            FilterExpressionBuilder builder,
            Map<String, Object> criteria) {

        List<FilterExpressionBuilder.Op> ops = new ArrayList<>();

        for (Map.Entry<String, Object> entry : criteria.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

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

    private void optimizePgVectorIndex() {
        try {
            
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

                jdbcTemplate.execute(String.format("SET hnsw.ef_search = %d;",
                    properties.getHnsw().getEfSearch()));
            }

            jdbcTemplate.execute("ANALYZE vector_store;");
            
        } catch (Exception e) {

        }
    }

    private void ensureDocumentId(Document document) {
        if (!document.getMetadata().containsKey("id")) {
            document.getMetadata().put("id", UUID.randomUUID().toString());
        }
    }

    private void ensureTimestamp(Document document) {
        if (!document.getMetadata().containsKey("timestamp")) {
            document.getMetadata().put("timestamp", 
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        }
    }

    public List<Document> readPdfDocument(Resource pdfResource) {

        TextReader reader = new TextReader(pdfResource);
        return reader.get();
    }

    public List<Document> readTextDocument(Resource textResource) {
        TextReader reader = new TextReader(textResource);
        return reader.get();
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        stats.putAll(metrics);

        try {
            Long documentCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM vector_store",
                Long.class
            );
            stats.put("totalDocuments", documentCount);

            String indexSizeStr = jdbcTemplate.queryForObject(
                "SELECT pg_size_pretty(pg_relation_size('embedding_hnsw_idx'))::text",
                String.class
            );
            stats.put("indexSize", indexSizeStr != null ? indexSizeStr : "0 bytes");
            
        } catch (Exception e) {
            
        }
        
        return stats;
    }

    public void shutdown() {
        executorService.shutdown();
    }

    private static class KeywordDocumentTransformer implements DocumentTransformer {
        private static final int MAX_KEYWORDS = 5;
        
        @Override
        public List<Document> apply(List<Document> documents) {
            for (Document doc : documents) {
                String content = doc.getText();
                if (content != null && !content.isEmpty()) {
                    
                    Set<String> keywords = extractKeywords(content);
                    doc.getMetadata().put("keywords", new ArrayList<>(keywords));
                }
            }
            return documents;
        }
        
        private Set<String> extractKeywords(String content) {
            
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