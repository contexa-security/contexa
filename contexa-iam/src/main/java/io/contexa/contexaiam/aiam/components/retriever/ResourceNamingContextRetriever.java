package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;

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

    public ResourceNamingContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        super(vectorStore, ragProperties);
        this.contextRetrieverRegistry = contextRetrieverRegistry;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        contextRetrieverRegistry.registerRetriever(ResourceNamingContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> req) {
        if (!(req instanceof ResourceNamingSuggestionRequest request)) {
            return super.retrieveContext(req);
        }

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
        return "";
    }
}
