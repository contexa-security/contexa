package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 리소스 네이밍을 위한 컨텍스트 검색기
 * RAG 패턴으로 관련 리소스 네이밍 히스토리를 검색
 */
@Slf4j
@Component
public class ResourceNamingContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final ResourceNamingVectorService vectorService;
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Value("${spring.ai.rag.naming.similarity-threshold:0.7}")
    private double namingSimilarityThreshold;
    
    @Value("${spring.ai.rag.naming.top-k:10}")
    private int namingTopK;
    
    private RetrievalAugmentationAdvisor namingAdvisor;

    public ResourceNamingContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ResourceNamingVectorService vectorService) {
        super(vectorStore);
        this.contextRetrieverRegistry = contextRetrieverRegistry;
        this.vectorService = vectorService;
    }

    /**
     * Spring ApplicationContext가 완전히 초기화된 후 호출됩니다.
     * ServletContext, JPA EntityManager, BeanPostProcessor 등이 모두 준비된 상태에서 실행됩니다.
     *
     * @param event ContextRefreshedEvent
     */
    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        log.info("ApplicationContext refreshed. Initializing ResourceNamingContextRetriever...");
        registerSelf();
    }

    private void registerSelf() {
        // RAG Advisor 생성 (사용 가능한 경우)
        if (chatClientBuilder != null && vectorStore != null) {
            createNamingAdvisor();
        }

        contextRetrieverRegistry.registerRetriever(ResourceNamingContext.class, this);
        log.info("ResourceNamingContextRetriever 자동 등록 완료 (Spring AI RAG 지원)");
    }
    
    /**
     * 리소스 네이밍 전용 RAG Advisor 생성
     */
    private void createNamingAdvisor() {
        // 네이밍 쿼리 변환기
        QueryTransformer namingQueryTransformer = new NamingQueryTransformer(chatClientBuilder);
        
        // 네이밍 필터 구성
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "naming", "resource", "identifier", "convention"),
            filterBuilder.gte("relevanceScore", 0.65)
        ).build();
        
        // VectorStoreDocumentRetriever 구성
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(namingSimilarityThreshold)
            .topK(namingTopK)
            .filterExpression(filter)
            .build();
        
        // Naming RAG Advisor 생성
        namingAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(namingQueryTransformer)
            .build();
        
        // 부모 클래스에 Advisor 등록
        registerDomainAdvisor(ResourceNamingContext.class, namingAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> req) {
        if (!(req instanceof ResourceNamingSuggestionRequest)) {
            return super.retrieveContext(req);
        }
        
        ResourceNamingSuggestionRequest request = (ResourceNamingSuggestionRequest) req;
        if (request.getResources() == null || request.getResources().isEmpty()) {
            log.debug("검색할 리소스가 없습니다");
            return new ContextRetrievalResult(null, List.of(), Map.of());
        }

        try {
            // VectorService에 요청 저장
            try {
                vectorService.storeNamingRequest(request);
                log.debug("💾 VectorService에 네이밍 요청 저장 완료");
            } catch (Exception e) {
                log.warn("VectorService 요청 저장 실패: {}", e.getMessage());
            }
            
            // RAG 기반 검색 시도
            ContextRetrievalResult ragResult = null;
            if (namingAdvisor != null) {
                ragResult = super.retrieveContext(req);
            }
            // 모든 리소스 식별자를 조합하여 검색 쿼리 생성
            String searchQuery = buildSearchQuery(request);
            log.debug("RAG 검색 쿼리: {}", searchQuery);

            // 1. VectorService를 통한 유사 네이밍 패턴 검색
            List<Document> vectorServiceDocs = List.of();
            try {
                String identifier = request.getResources().isEmpty() ? "" : 
                    request.getResources().get(0).getIdentifier();
                vectorServiceDocs = vectorService.findSimilarNamings(identifier, 5);
                log.debug("VectorService에서 {}개의 유사 네이밍 발견", vectorServiceDocs.size());
            } catch (Exception e) {
                log.warn("VectorService 검색 실패: {}", e.getMessage());
            }
            
            // 2. RAG 결과가 없으면 기본 검색
            List<Document> similarDocs = new ArrayList<>();
            similarDocs.addAll(vectorServiceDocs);
            
            if (ragResult != null && ragResult.getDocuments() != null) {
                for (Document doc : ragResult.getDocuments()) {
                    boolean isDuplicate = similarDocs.stream()
                        .anyMatch(existing -> existing.getText().equals(doc.getText()));
                    if (!isDuplicate) {
                        similarDocs.add(doc);
                    }
                }
            } else {
                // 폴백: 기본 Vector Store 검색
                SearchRequest searchRequest = SearchRequest.builder()
                        .query(searchQuery)
                        .topK(namingTopK - vectorServiceDocs.size())
                        .similarityThreshold(namingSimilarityThreshold)
                        .build();
                List<Document> storeDocs = vectorStore.similaritySearch(searchRequest);
                for (Document doc : storeDocs) {
                    boolean isDuplicate = similarDocs.stream()
                        .anyMatch(existing -> existing.getText().equals(doc.getText()));
                    if (!isDuplicate) {
                        similarDocs.add(doc);
                    }
                }
            }

            if (similarDocs.isEmpty()) {
                log.debug("유사한 리소스 네이밍 사례를 찾지 못했습니다");
                return new ContextRetrievalResult(null, List.of(), Map.of("message", "No similar naming cases found"));
            }

            // 검색된 문서들을 컨텍스트로 변환
            String context = buildContextFromDocuments(similarDocs);
            log.debug("RAG 컨텍스트 검색 완료 - 문서 수: {}, 컨텍스트 길이: {}",
                    similarDocs.size(), context.length());

            Map<String, Object> metadata = new HashMap<>();
            if (ragResult != null) {
                metadata.putAll(ragResult.getMetadata());
            }
            metadata.put("retrieverType", "ResourceNamingContextRetriever");
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("ragEnabled", namingAdvisor != null);
            
            return new ContextRetrievalResult(context, similarDocs, metadata);

        } catch (Exception e) {
            log.error("RAG 컨텍스트 검색 중 오류 발생", e);
            return new ContextRetrievalResult(null, List.of(), Map.of("error", e.getMessage()));
        }
    }

    /**
     * 리소스 목록에서 검색 쿼리 생성
     */
    private String buildSearchQuery(ResourceNamingSuggestionRequest request) {
        // 리소스 식별자들을 분석하여 검색에 유용한 키워드 추출
        List<String> keywords = request.getResources().stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier)
                .flatMap(identifier -> extractKeywords(identifier).stream())
                .distinct()
                .collect(Collectors.toList());

        // 서비스 소유자 정보도 추가
        List<String> owners = request.getResources().stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::getOwner)
                .filter(owner -> owner != null && !owner.trim().isEmpty())
                .distinct()
                .collect(Collectors.toList());

        StringBuilder query = new StringBuilder();
        query.append("리소스 네이밍 사례: ");
        query.append(String.join(", ", keywords));
        
        if (!owners.isEmpty()) {
            query.append(" 소유자: ").append(String.join(", ", owners));
        }

        return query.toString();
    }

    /**
     * 리소스 식별자에서 키워드 추출
     */
    private List<String> extractKeywords(String identifier) {
        if (identifier == null || identifier.trim().isEmpty()) {
            return List.of();
        }

        // URL 경로에서 키워드 추출
        if (identifier.startsWith("/")) {
            return List.of(identifier.split("/"))
                    .stream()
                    .filter(part -> !part.isEmpty() && !part.matches("\\{.*\\}")) // 경로 변수 제외
                    .collect(Collectors.toList());
        }

        // 메서드명에서 키워드 추출
        if (identifier.contains(".")) {
            String[] parts = identifier.split("\\.");
            String methodName = parts[parts.length - 1].replace("()", "");
            
            // camelCase 분리
            String[] camelParts = methodName.split("(?=\\p{Upper})");
            return List.of(camelParts);
        }

        // 기본적으로 전체 식별자를 키워드로 사용
        return List.of(identifier);
    }

    /**
     * 검색된 문서들을 컨텍스트 문자열로 변환
     */
    private String buildContextFromDocuments(List<Document> documents) {
        StringBuilder context = new StringBuilder();
        context.append("유사한 리소스 네이밍 사례들:\n\n");

        for (int i = 0; i < documents.size(); i++) {
            Document doc = documents.get(i);
            context.append(i + 1).append(". ");
            
            // 메타데이터가 있으면 활용
            if (doc.getMetadata().containsKey("identifier")) {
                context.append("식별자: ").append(doc.getMetadata().get("identifier"));
            }
            if (doc.getMetadata().containsKey("friendlyName")) {
                context.append(" → 친화적 이름: ").append(doc.getMetadata().get("friendlyName"));
            }
            
            context.append("\n");
            
            // 문서 내용 추가 (너무 길면 자르기)
            String content = doc.getText();
            if (content.length() > 200) {
                content = content.substring(0, 200) + "...";
            }
            context.append("   설명: ").append(content).append("\n\n");
        }

        return context.toString();
    }

    public String getRetrieverName() {
        return "resource-naming-context";
    }
    
    /**
     * 네이밍 쿼리 변환기
     */
    private static class NamingQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public NamingQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                리소스 네이밍 검색을 위한 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. 리소스 타입과 카테고리를 구체화하세요
                2. 네이밍 컨벤션과 패턴 관련 용어를 추가하세요
                3. API, REST, 메서드 등 기술적 컨텍스트를 포함하세요
                4. 카멜케이스, 스네이크케이스 등 네이밍 스타일을 고려하세요
                5. 서비스 소유자와 도메인 컨텍스트를 포함하세요
                
                최적화된 쿼리만 반환하세요.
                """, originalQuery.text());
            
            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();
                
            return new Query(transformedText);
        }
    }
} 