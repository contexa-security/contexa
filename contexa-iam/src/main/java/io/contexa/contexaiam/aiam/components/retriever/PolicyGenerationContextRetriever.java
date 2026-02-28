package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.List;
import java.util.Map;

/**
 * RAG-focused context retriever for Policy Generation.
 * <p>
 * Responsibility: Vector search only (similar policy patterns).
 * DB queries for available items (roles, permissions, conditions) are handled by
 * AdvancedPolicyGenerationLab via IAMDataCollectionService.
 * </p>
 */
@Slf4j
public class PolicyGenerationContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final PolicyGenerationVectorService vectorService;

    public PolicyGenerationContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            PolicyGenerationVectorService vectorService,
            ContexaRagProperties ragProperties) {
        super(vectorStore, ragProperties);
        this.contextRetrieverRegistry = contextRetrieverRegistry;
        this.vectorService = vectorService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        contextRetrieverRegistry.registerRetriever(PolicyContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof PolicyContext) {
            String contextInfo = retrieveRagContext(request);
            return new ContextRetrievalResult(
                    contextInfo,
                    List.of(),
                    Map.of("retrieverType", "PolicyGenerationContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }
        return super.retrieveContext(request);
    }

    private String retrieveRagContext(AIRequest<?> request) {
        try {
            String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
            if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
                naturalLanguageQuery = request.getNaturalLanguageQuery();
            }

            if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
                return "";
            }

            return searchSimilarPolicyPatterns(naturalLanguageQuery);
        } catch (Exception e) {
            log.error("Failed to retrieve RAG context for policy generation", e);
            return "";
        }
    }

    private String searchSimilarPolicyPatterns(String naturalLanguageQuery) {
        try {
            List<Document> similarPolicies = List.of();
            try {
                similarPolicies = vectorService.findSimilarPolicies(naturalLanguageQuery, 5);
            } catch (Exception e) {
                log.error("VectorService policy search failed: {}", e.getMessage());
            }

            if (similarPolicies.isEmpty()) {
                return "";
            }

            StringBuilder patterns = new StringBuilder();
            patterns.append("### Similar Policy Generation Cases:\n");

            for (int i = 0; i < Math.min(similarPolicies.size(), 8); i++) {
                Document doc = similarPolicies.get(i);
                String text = doc.getText();
                if (text.length() > 300) {
                    text = text.substring(0, 300) + "...";
                }
                patterns.append(String.format("%d. %s\n", i + 1, text));

                if (doc.getMetadata().containsKey("policyType")) {
                    patterns.append("   - Policy Type: ").append(doc.getMetadata().get("policyType")).append("\n");
                }
            }

            return patterns.toString();

        } catch (Exception e) {
            log.error("Failed to search similar policy patterns: {}", e.getMessage());
            return "";
        }
    }
}
