package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.properties.ContexaRagProperties;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ContextRetriever {

    protected final VectorStore vectorStore;
    private final ContexaRagProperties ragProperties;

    public ContextRetriever(VectorStore vectorStore, ContexaRagProperties ragProperties) {
        this.vectorStore = vectorStore;
        this.ragProperties = ragProperties;
    }

    public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
        String query = extractQueryFromRequest(request);

        SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(ragProperties.getDefaults().getTopK())
                .similarityThreshold(ragProperties.getDefaults().getSimilarityThreshold())
                .build();

        List<Document> contextDocs = vectorStore.similaritySearch(searchRequest);

        String contextInfo = contextDocs.stream()
                .map(doc -> "- " + doc.getText())
                .collect(Collectors.joining("\n"));

        Map<String, Object> metadata = Map.of(
                "documentsFound", contextDocs.size(),
                "searchQuery", query
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
