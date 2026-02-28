package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.List;
import java.util.Map;

/**
 * RAG-focused context retriever for Studio Query.
 * <p>
 * Responsibility: Vector search only (similar query patterns).
 * DB queries for IAM data are handled by StudioQueryLab via IAMDataCollectionService.
 * </p>
 */
@Slf4j
public class StudioQueryContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;
    private final StudioQueryVectorService vectorService;

    public StudioQueryContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            StudioQueryVectorService vectorService,
            ContexaRagProperties ragProperties) {
        super(vectorStore, ragProperties);
        this.registry = registry;
        this.vectorService = vectorService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        registry.registerRetriever(StudioQueryContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof StudioQueryContext) {
            String contextInfo = retrieveRagContext(request);
            return new ContextRetrievalResult(
                    contextInfo,
                    List.of(),
                    Map.of("retrieverType", "StudioQueryContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }
        return super.retrieveContext(request);
    }

    /**
     * Retrieves RAG context only - similar query patterns from vector store.
     */
    private String retrieveRagContext(AIRequest<?> request) {
        try {
            String naturalQuery = request.getNaturalLanguageQuery();
            if (naturalQuery == null || naturalQuery.trim().isEmpty()) {
                return "";
            }
            return searchSimilarQueryPatterns(naturalQuery);
        } catch (Exception e) {
            log.error("Failed to retrieve RAG context", e);
            return "";
        }
    }

    private String searchSimilarQueryPatterns(String naturalQuery) {
        try {
            List<Document> similarQueries = vectorService.findSimilarQueries(naturalQuery, 5);

            if (similarQueries.isEmpty()) {
                return "";
            }

            StringBuilder patterns = new StringBuilder();
            patterns.append("### Similar Query Cases:\n");

            for (int i = 0; i < Math.min(similarQueries.size(), 8); i++) {
                Document doc = similarQueries.get(i);
                patterns.append(String.format("%d. %s\n", i + 1, doc.getText()));
            }

            return patterns.toString();

        } catch (Exception e) {
            log.error("Failed to search similar query patterns: {}", e.getMessage());
            return "";
        }
    }
}
