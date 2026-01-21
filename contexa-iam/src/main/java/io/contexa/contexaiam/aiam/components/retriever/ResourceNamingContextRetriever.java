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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
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

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
                registerSelf();
    }

    private void registerSelf() {
        
        if (chatClientBuilder != null && vectorStore != null) {
            createNamingAdvisor();
        }

        contextRetrieverRegistry.registerRetriever(ResourceNamingContext.class, this);
            }

    private void createNamingAdvisor() {
        
        QueryTransformer namingQueryTransformer = new NamingQueryTransformer(chatClientBuilder);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "naming", "resource", "identifier", "convention"),
            filterBuilder.gte("relevanceScore", 0.65)
        ).build();

        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(namingSimilarityThreshold)
            .topK(namingTopK)
            .filterExpression(filter)
            .build();

        namingAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(namingQueryTransformer)
            .build();

        registerDomainAdvisor(ResourceNamingContext.class, namingAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> req) {
        if (!(req instanceof ResourceNamingSuggestionRequest)) {
            return super.retrieveContext(req);
        }
        
        ResourceNamingSuggestionRequest request = (ResourceNamingSuggestionRequest) req;
        if (request.getResources() == null || request.getResources().isEmpty()) {
                        return new ContextRetrievalResult(null, List.of(), Map.of());
        }

        try {
            
            try {
                vectorService.storeNamingRequest(request);
                            } catch (Exception e) {
                log.warn("VectorService 요청 저장 실패: {}", e.getMessage());
            }

            ContextRetrievalResult ragResult = null;
            if (namingAdvisor != null) {
                ragResult = super.retrieveContext(req);
            }
            
            String searchQuery = buildSearchQuery(request);

            List<Document> vectorServiceDocs = List.of();
            try {
                String identifier = request.getResources().isEmpty() ? "" : 
                    request.getResources().get(0).getIdentifier();
                vectorServiceDocs = vectorService.findSimilarNamings(identifier, 5);
                            } catch (Exception e) {
                log.warn("VectorService 검색 실패: {}", e.getMessage());
            }

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
                                return new ContextRetrievalResult(null, List.of(), Map.of("message", "No similar naming cases found"));
            }

            String context = buildContextFromDocuments(similarDocs);
            
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

    private String buildSearchQuery(ResourceNamingSuggestionRequest request) {
        
        List<String> keywords = request.getResources().stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier)
                .flatMap(identifier -> extractKeywords(identifier).stream())
                .distinct()
                .collect(Collectors.toList());

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

    private List<String> extractKeywords(String identifier) {
        if (identifier == null || identifier.trim().isEmpty()) {
            return List.of();
        }

        if (identifier.startsWith("/")) {
            return List.of(identifier.split("/"))
                    .stream()
                    .filter(part -> !part.isEmpty() && !part.matches("\\{.*\\}")) 
                    .collect(Collectors.toList());
        }

        if (identifier.contains(".")) {
            String[] parts = identifier.split("\\.");
            String methodName = parts[parts.length - 1].replace("()", "");

            String[] camelParts = methodName.split("(?=\\p{Upper})");
            return List.of(camelParts);
        }

        return List.of(identifier);
    }

    private String buildContextFromDocuments(List<Document> documents) {
        StringBuilder context = new StringBuilder();
        context.append("유사한 리소스 네이밍 사례들:\n\n");

        for (int i = 0; i < documents.size(); i++) {
            Document doc = documents.get(i);
            context.append(i + 1).append(". ");

            if (doc.getMetadata().containsKey("identifier")) {
                context.append("식별자: ").append(doc.getMetadata().get("identifier"));
            }
            if (doc.getMetadata().containsKey("friendlyName")) {
                context.append(" → 친화적 이름: ").append(doc.getMetadata().get("friendlyName"));
            }
            
            context.append("\n");

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