package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Spring AI RAG 기반 컨텍스트 검색기
 *
 * Spring AI 표준 RetrievalAugmentationAdvisor를 활용한 컨텍스트 검색
 * - 도메인별 RAG Advisor 관리
 * - Pre-Retrieval 쿼리 변환
 * - Post-Retrieval 문서 처리
 * - 다양한 검색 전략 지원
 */
public class ContextRetriever {

    protected final VectorStore vectorStore;
    private final Map<Class<? extends DomainContext>, RetrievalAugmentationAdvisor> domainAdvisors = new ConcurrentHashMap<>();
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Autowired(required = false)
    @Qualifier("temporalClusteringProcessor")
    private DocumentPostProcessor temporalClusteringProcessor;
    
    @Autowired(required = false)
    @Qualifier("anomalyScoreRanker")
    private DocumentPostProcessor anomalyScoreRanker;
    
    @Value("${spring.ai.rag.default.similarity-threshold:0.7}")
    private double defaultSimilarityThreshold;
    
    @Value("${spring.ai.rag.default.top-k:10}")
    private int defaultTopK;
    
    @Value("${spring.ai.rag.default.enable-query-rewrite:false}")
    private boolean enableQueryRewrite;
    
    private RetrievalAugmentationAdvisor defaultAdvisor;

    public ContextRetriever(VectorStore vectorStore) {
        this.vectorStore = vectorStore;
    }
    
    @PostConstruct
    public void initialize() {
        // Spring AI RAG가 활성화된 경우 기본 Advisor 생성
        if (chatClientBuilder != null && enableQueryRewrite) {
            initializeDefaultRagAdvisor();
        }
    }

    /**
     * 자연어 쿼리를 기반으로 관련 컨텍스트를 검색합니다
     *
     * @param request AI 요청 (자연어 쿼리 포함)
     * @return 검색된 컨텍스트 정보
     */
    public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
        String query = extractQueryFromRequest(request);
        
        // RAG Advisor가 있으면 사용, 없으면 기본 검색
        RetrievalAugmentationAdvisor advisor = selectAdvisor(request);
        
        List<Document> contextDocs;
        if (advisor != null) {
            // Spring AI RAG 검색
            contextDocs = performRagRetrieval(advisor, query);
        } else {
            // 기본 Vector DB 검색
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(defaultTopK)
                    .similarityThreshold(defaultSimilarityThreshold)
                    .build();
            contextDocs = vectorStore.similaritySearch(searchRequest);
        }

        // 2. 검색 결과 정제
        String contextInfo = contextDocs.stream()
                .map(doc -> "- " + doc.getText())
                .collect(Collectors.joining("\n"));

        // 3. 메타데이터 수집
        Map<String, Object> metadata = Map.of(
                "documentsFound", contextDocs.size(),
                "searchQuery", query,
                "retrievalTime", System.currentTimeMillis(),
                "ragEnabled", advisor != null
        );

        return new ContextRetrievalResult(contextInfo, contextDocs, metadata);
    }

    /**
     * 요청에서 검색 쿼리를 추출합니다
     */
    protected String extractQueryFromRequest(AIRequest<? extends DomainContext> request) {
        String query = request.getParameter("naturalLanguageQuery", String.class);
        if (query == null || query.isEmpty()) {
            // 컨텍스트에서 쿼리 생성 시도
            DomainContext context = request.getContext();
            if (context != null) {
                query = context.toString();
            }
        }
        return query;
    }
    
    /**
     * 도메인별 RAG Advisor 등록
     */
    public void registerDomainAdvisor(
            Class<? extends DomainContext> domainClass,
            RetrievalAugmentationAdvisor advisor) {
        domainAdvisors.put(domainClass, advisor);
    }
    
    /**
     * 도메인에 맞는 RAG Advisor 선택
     */
    private RetrievalAugmentationAdvisor selectAdvisor(AIRequest<? extends DomainContext> request) {
        if (request.getContext() == null) {
            return defaultAdvisor;
        }
        
        Class<?> contextClass = request.getContext().getClass();
        
        // 정확한 클래스 매칭
        RetrievalAugmentationAdvisor advisor = domainAdvisors.get(contextClass);
        if (advisor != null) {
            return advisor;
        }
        
        // 상위 클래스/인터페이스 매칭
        for (Map.Entry<Class<? extends DomainContext>, RetrievalAugmentationAdvisor> entry : domainAdvisors.entrySet()) {
            if (entry.getKey().isAssignableFrom(contextClass)) {
                return entry.getValue();
            }
        }
        
        return defaultAdvisor;
    }
    
    /**
     * RAG 기반 문서 검색 실행
     */
    private List<Document> performRagRetrieval(
            RetrievalAugmentationAdvisor advisor,
            String query) {
        
        // Spring AI RAG Advisor는 내부적으로 다음을 수행:
        // 1. Query Rewriting (Pre-Retrieval)
        // 2. Vector Store 검색
        // 3. Document Post-Processing
        
        // 여기서는 직접 VectorStore 검색 (Advisor 내부 로직 시뮬레이션)
        SearchRequest searchRequest = SearchRequest.builder()
            .query(query)
            .topK(defaultTopK)
            .similarityThreshold(defaultSimilarityThreshold)
            .build();
        
        List<Document> documents = vectorStore.similaritySearch(searchRequest);
        
        // Post-Processing 적용 (있는 경우)
        if (temporalClusteringProcessor != null) {
            documents = temporalClusteringProcessor.process(new Query(query), documents);
        }
        if (anomalyScoreRanker != null) {
            documents = anomalyScoreRanker.process(new Query(query), documents);
        }
        
        return documents;
    }
    
    /**
     * 기본 RAG Advisor 초기화
     */
    private void initializeDefaultRagAdvisor() {
        if (chatClientBuilder == null) {
            return;
        }
        
        // 기본 쿼리 변환기
        QueryTransformer defaultQueryTransformer = new DefaultQueryTransformer(chatClientBuilder);
        
        // 기본 Advisor 생성
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(defaultSimilarityThreshold)
            .topK(defaultTopK)
            .build();
            
        defaultAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(defaultQueryTransformer)
            .build();
    }
    
    /**
     * 기본 쿼리 변환기
     */
    private static class DefaultQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public DefaultQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null || originalQuery.text().isEmpty()) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                다음 검색 쿼리를 최적화하세요:
                원본: %s
                최적화된 쿼리만 반환하세요.
                """, originalQuery.text());
            
            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();
            
            return new Query(transformedText);
        }
    }

    /**
     * 컨텍스트 검색 결과
     */
    public static class ContextRetrievalResult {
        private final String contextInfo;
        private final List<Document> documents;
        private final Map<String, Object> metadata;

        public ContextRetrievalResult(String contextInfo, List<Document> documents, Map<String, Object> metadata) {
            this.contextInfo = contextInfo;
            this.documents = documents;
            this.metadata = metadata;
        }

        public String getContextInfo() { return contextInfo; }
        public List<Document> getDocuments() { return documents; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
}