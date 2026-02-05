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
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * RAG-focused context retriever for Resource Naming.
 * <p>
 * Responsibility: Vector search only (similar naming patterns).
 * </p>
 */
@Slf4j
public class ResourceNamingContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final ResourceNamingVectorService vectorService;

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
        contextRetrieverRegistry.registerRetriever(ResourceNamingContext.class, this);
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
            String contextInfo = retrieveRagContext(request);
            return new ContextRetrievalResult(
                    contextInfo,
                    List.of(),
                    Map.of("retrieverType", "ResourceNamingContextRetriever", "timestamp", System.currentTimeMillis())
            );
        } catch (Exception e) {
            log.error("Failed to retrieve RAG context for resource naming", e);
            return new ContextRetrievalResult(null, List.of(), Map.of("error", e.getMessage()));
        }
    }

    private String retrieveRagContext(ResourceNamingSuggestionRequest request) {
        try {
            String identifier = request.getResources().isEmpty() ? "" :
                    request.getResources().get(0).getIdentifier();

            if (identifier == null || identifier.trim().isEmpty()) {
                return "";
            }

            return searchSimilarNamingPatterns(request, identifier);
        } catch (Exception e) {
            log.error("Failed to retrieve RAG context", e);
            return "";
        }
    }

    private String searchSimilarNamingPatterns(ResourceNamingSuggestionRequest request, String identifier) {
        try {
            List<Document> vectorServiceDocs = List.of();
            try {
                vectorServiceDocs = vectorService.findSimilarNamings(identifier, 5);
            } catch (Exception e) {
                log.warn("VectorService naming search failed: {}", e.getMessage());
            }

            String searchQuery = buildSearchQuery(request);
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(searchQuery)
                    .topK(3)
                    .similarityThreshold(0.6)
                    .build();
            List<Document> vectorDocs = vectorStore.similaritySearch(searchRequest);

            List<Document> allDocs = new ArrayList<>(vectorServiceDocs);
            for (Document doc : vectorDocs) {
                boolean isDuplicate = allDocs.stream()
                        .anyMatch(existing -> existing.getText().equals(doc.getText()));
                if (!isDuplicate) {
                    allDocs.add(doc);
                }
            }

            if (allDocs.isEmpty()) {
                return "";
            }

            return buildContextFromDocuments(allDocs);

        } catch (Exception e) {
            log.error("Failed to search similar naming patterns: {}", e.getMessage());
            return "";
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
        query.append("Resource naming cases: ");
        query.append(String.join(", ", keywords));

        if (!owners.isEmpty()) {
            query.append(" Owner: ").append(String.join(", ", owners));
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
        context.append("### Similar Resource Naming Cases:\n\n");

        for (int i = 0; i < Math.min(documents.size(), 8); i++) {
            Document doc = documents.get(i);
            context.append(i + 1).append(". ");

            if (doc.getMetadata().containsKey("identifier")) {
                context.append("Identifier: ").append(doc.getMetadata().get("identifier"));
            }
            if (doc.getMetadata().containsKey("friendlyName")) {
                context.append(" -> Friendly Name: ").append(doc.getMetadata().get("friendlyName"));
            }

            context.append("\n");

            String content = doc.getText();
            if (content.length() > 200) {
                content = content.substring(0, 200) + "...";
            }
            context.append("   Description: ").append(content).append("\n\n");
        }

        return context.toString();
    }
}
