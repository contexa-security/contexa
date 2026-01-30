package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import jakarta.annotation.PostConstruct;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class ContextRetriever {

    protected final VectorStore vectorStore;
    private final Map<Class<? extends DomainContext>, RetrievalAugmentationAdvisor> domainAdvisors = new ConcurrentHashMap<>();
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;

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
        
        if (chatClientBuilder != null && enableQueryRewrite) {
            initializeDefaultRagAdvisor();
        }
    }

    public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
        String query = extractQueryFromRequest(request);

        RetrievalAugmentationAdvisor advisor = selectAdvisor(request);
        
        List<Document> contextDocs;
        if (advisor != null) {
            
            contextDocs = performRagRetrieval(advisor, query);
        } else {
            
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(defaultTopK)
                    .similarityThreshold(defaultSimilarityThreshold)
                    .build();
            contextDocs = vectorStore.similaritySearch(searchRequest);
        }

        String contextInfo = contextDocs.stream()
                .map(doc -> "- " + doc.getText())
                .collect(Collectors.joining("\n"));

        Map<String, Object> metadata = Map.of(
                "documentsFound", contextDocs.size(),
                "searchQuery", query,
                "retrievalTime", System.currentTimeMillis(),
                "ragEnabled", advisor != null
        );

        return new ContextRetrievalResult(contextInfo, contextDocs, metadata);
    }

    protected String extractQueryFromRequest(AIRequest<? extends DomainContext> request) {
        String query = request.getParameter("naturalLanguageQuery", String.class);
        if (query == null || query.isEmpty()) {
            
            DomainContext context = request.getContext();
            if (context != null) {
                query = context.toString();
            }
        }
        return query;
    }

    public void registerDomainAdvisor(
            Class<? extends DomainContext> domainClass,
            RetrievalAugmentationAdvisor advisor) {
        domainAdvisors.put(domainClass, advisor);
    }

    private RetrievalAugmentationAdvisor selectAdvisor(AIRequest<? extends DomainContext> request) {
        if (request.getContext() == null) {
            return defaultAdvisor;
        }
        
        Class<?> contextClass = request.getContext().getClass();

        RetrievalAugmentationAdvisor advisor = domainAdvisors.get(contextClass);
        if (advisor != null) {
            return advisor;
        }

        for (Map.Entry<Class<? extends DomainContext>, RetrievalAugmentationAdvisor> entry : domainAdvisors.entrySet()) {
            if (entry.getKey().isAssignableFrom(contextClass)) {
                return entry.getValue();
            }
        }
        
        return defaultAdvisor;
    }

    private List<Document> performRagRetrieval(
            RetrievalAugmentationAdvisor advisor,
            String query) {

        SearchRequest searchRequest = SearchRequest.builder()
            .query(query)
            .topK(defaultTopK)
            .similarityThreshold(defaultSimilarityThreshold)
            .build();

        return vectorStore.similaritySearch(searchRequest);
    }

    private void initializeDefaultRagAdvisor() {
        if (chatClientBuilder == null) {
            return;
        }

        QueryTransformer defaultQueryTransformer = new DefaultQueryTransformer(chatClientBuilder);

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
                Optimize the following search query:
                Original: %s
                Return only the optimized query.
                """, originalQuery.text());

            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();

            return new Query(transformedText);
        }
    }

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