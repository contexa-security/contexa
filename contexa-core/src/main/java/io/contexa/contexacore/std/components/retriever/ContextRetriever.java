package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.rag.service.VectorFilterExpressionBuilder;
import io.contexa.contexacore.std.rag.service.VectorOperations;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ContextRetriever {

    protected final VectorOperations vectorOperations;
    protected final ContexaRagProperties ragProperties;

    public ContextRetriever(VectorStore vectorStore, ContexaRagProperties ragProperties) {
        this(new DirectVectorStoreOperations(vectorStore), ragProperties);
    }

    public ContextRetriever(VectorOperations vectorOperations, ContexaRagProperties ragProperties) {
        this.vectorOperations = vectorOperations;
        this.ragProperties = ragProperties;
    }

    public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
        String query = extractQueryFromRequest(request);

        SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(ragProperties.getDefaults().getTopK())
                .similarityThreshold(ragProperties.getDefaults().getSimilarityThreshold())
                .build();

        List<Document> contextDocs = vectorOperations.searchSimilar(searchRequest);

        String contextInfo = contextDocs.stream()
                .map(doc -> "- " + doc.getText())
                .collect(Collectors.joining("\n"));

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentsFound", contextDocs.size());
        metadata.put("searchQuery", query);

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

    private static final class DirectVectorStoreOperations implements VectorOperations {

        private final VectorStore vectorStore;

        private DirectVectorStoreOperations(VectorStore vectorStore) {
            this.vectorStore = vectorStore;
        }

        @Override
        public void storeDocument(Document document) {
            if (vectorStore == null) {
                return;
            }
            vectorStore.add(List.of(document));
        }

        @Override
        public void storeDocuments(List<Document> documents) {
            if (vectorStore == null || documents == null || documents.isEmpty()) {
                return;
            }
            vectorStore.add(documents);
        }

        @Override
        public List<Document> searchSimilar(String query) {
            if (vectorStore == null) {
                return List.of();
            }
            SearchRequest request = SearchRequest.builder()
                    .query(query)
                    .topK(5)
                    .build();
            return vectorStore.similaritySearch(request);
        }

        @Override
        public List<Document> searchSimilar(String query, Map<String, Object> filters) {
            SearchRequest.Builder builder = SearchRequest.builder().query(query).topK(5);
            if (filters != null && !filters.isEmpty()) {
                String filterExpression = VectorFilterExpressionBuilder.buildEqualityExpression(filters);
                if (filterExpression != null) {
                    builder.filterExpression(filterExpression);
                }
            }
            return searchSimilar(builder.build());
        }

        @Override
        public List<Document> searchSimilar(SearchRequest request) {
            if (vectorStore == null) {
                return List.of();
            }
            return vectorStore.similaritySearch(request);
        }

        @Override
        public void deleteDocuments(List<String> documentIds) {
            if (vectorStore == null || documentIds == null || documentIds.isEmpty()) {
                return;
            }
            vectorStore.delete(documentIds);
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
