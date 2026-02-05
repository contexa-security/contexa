package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * RAG-focused context retriever for Condition Template generation.
 * <p>
 * Responsibility: Vector search only (similar condition templates).
 * Prompt generation logic is handled by PromptTemplate classes.
 * </p>
 */
@Slf4j
public class ConditionTemplateContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;
    private final ConditionTemplateVectorService vectorService;

    public ConditionTemplateContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            ConditionTemplateVectorService vectorService) {
        super(vectorStore);
        this.registry = registry;
        this.vectorService = vectorService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        registry.registerRetriever(ConditionTemplateContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof ConditionTemplateContext) {
            String contextInfo = retrieveRagContext(request);
            return new ContextRetrievalResult(
                    contextInfo,
                    List.of(),
                    Map.of("retrieverType", "ConditionTemplateContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }
        return super.retrieveContext(request);
    }

    private String retrieveRagContext(AIRequest<?> request) {
        try {
            ConditionTemplateContext context = (ConditionTemplateContext) request.getContext();
            if (context == null) {
                return "";
            }

            String resourceIdentifier = context.getResourceIdentifier();
            if (resourceIdentifier == null || resourceIdentifier.trim().isEmpty()) {
                return "";
            }

            return searchSimilarConditions(resourceIdentifier, context.getTemplateType());
        } catch (Exception e) {
            log.error("Failed to retrieve RAG context for condition template", e);
            return "";
        }
    }

    private String searchSimilarConditions(String resourceIdentifier, String templateType) {
        try {
            String methodName = extractMethodName(resourceIdentifier);

            List<Document> methodConditions = List.of();
            try {
                methodConditions = vectorService.findMethodConditions(methodName, 5);
            } catch (Exception e) {
                log.warn("VectorService method conditions search failed: {}", e.getMessage());
            }

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(resourceIdentifier + " " + (templateType != null ? templateType : ""))
                    .topK(3)
                    .similarityThreshold(0.6)
                    .build();
            List<Document> vectorDocs = vectorStore.similaritySearch(searchRequest);

            List<Document> allDocs = new ArrayList<>(methodConditions);
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

            StringBuilder patterns = new StringBuilder();
            patterns.append("### Similar Condition Template Cases:\n");

            for (int i = 0; i < Math.min(allDocs.size(), 8); i++) {
                Document doc = allDocs.get(i);
                patterns.append(String.format("%d. %s\n", i + 1, doc.getText()));

                if (doc.getMetadata().containsKey("conditionType")) {
                    patterns.append("   - Condition Type: ").append(doc.getMetadata().get("conditionType")).append("\n");
                }
            }

            return patterns.toString();

        } catch (Exception e) {
            log.error("Failed to search similar condition templates: {}", e.getMessage());
            return "";
        }
    }

    private String extractMethodName(String resourceIdentifier) {
        if (resourceIdentifier == null || resourceIdentifier.trim().isEmpty()) {
            return "unknown";
        }

        int lastDotIndex = resourceIdentifier.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return resourceIdentifier;
        }

        String methodPart = resourceIdentifier.substring(lastDotIndex + 1);

        if (methodPart.contains("(")) {
            return methodPart.substring(0, methodPart.indexOf("("));
        }

        return methodPart;
    }
}
