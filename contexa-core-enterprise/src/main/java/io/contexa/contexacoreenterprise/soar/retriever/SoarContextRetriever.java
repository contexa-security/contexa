package io.contexa.contexacoreenterprise.soar.retriever;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacoreenterprise.properties.SoarProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class SoarContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;
    private final SoarProperties soarProperties;

    public SoarContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            SoarProperties soarProperties,
            ContexaRagProperties ragProperties) {
        super(vectorStore, ragProperties);
        this.registry = registry;
        this.soarProperties = soarProperties;
    }

    @PostConstruct
    public void registerSelf() {
        registry.registerRetriever(SoarContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof SoarContext) {
            return retrieveSoarContextWithRAG((AIRequest<SoarContext>) request);
        }
        return super.retrieveContext(request);
    }

    private ContextRetrievalResult retrieveSoarContextWithRAG(AIRequest<SoarContext> request) {

        try {

            ContextRetrievalResult baseResult = super.retrieveContext(request);

            SoarContext context = request.getContext();

            String enhancedContext = buildComprehensiveContext(
                    context,
                    baseResult.getContextInfo(),
                    baseResult.getDocuments()
            );

            Map<String, Object> metadata = new HashMap<>(baseResult.getMetadata());
            metadata.put("retrieverType", "SoarContextRetriever");
            metadata.put("incidentId", context.getIncidentId());
            if (context.getThreatLevel() != null) {
                metadata.put("threatLevel", context.getThreatLevel().toString());
            }
            metadata.put("soarEnhanced", true);

            return new ContextRetrievalResult(
                    enhancedContext,
                    baseResult.getDocuments(),
                    metadata
            );

        } catch (Exception e) {
            log.error("SOAR context analysis failed", e);
            return new ContextRetrievalResult(
                    getDefaultContext(),
                    List.of(),
                    Map.of("error", e.getMessage())
            );
        }
    }

    private String buildSearchQuery(SoarContext context) {
        StringBuilder query = new StringBuilder();

        if (context.getThreatType() != null) {
            query.append(context.getThreatType()).append(" ");
        }

        if (context.getDescription() != null) {
            query.append(context.getDescription()).append(" ");
        }

        if (context.getQueryIntent() != null) {
            query.append(context.getQueryIntent()).append(" ");
        }

        if (!context.getExtractedEntities().isEmpty()) {
            query.append(context.getExtractedEntities().values()).append(" ");
        }

        return query.toString().trim();
    }

    private String extractRagContext(List<Document> documents) {
        if (documents.isEmpty()) {
            return "";
        }

        return documents.stream()
                .map(doc -> {
                    String content = doc.getText();

                    if (doc.getMetadata() != null && !doc.getMetadata().isEmpty()) {
                        String source = doc.getMetadata().getOrDefault("source", "unknown").toString();
                        return String.format("[Source: %s]\n%s", source, content);
                    }
                    return content;
                })
                .collect(Collectors.joining("\n\n"));
    }

    private String buildComprehensiveContext(SoarContext context, String baseContext, List<Document> documents) {
        String ragContext = extractRagContext(documents);
        StringBuilder contextBuilder = new StringBuilder();

        contextBuilder.append("## SOAR Analysis Context\n\n");

        contextBuilder.append("### Incident Information\n");
        contextBuilder.append(String.format("- Incident ID: %s\n", context.getIncidentId()));
        contextBuilder.append(String.format("- Threat Type: %s\n", context.getThreatType()));
        contextBuilder.append(String.format("- Description: %s\n", context.getDescription()));
        contextBuilder.append(String.format("- Affected Assets: %s\n",
            context.getAffectedAssets() != null ? String.join(", ", context.getAffectedAssets()) : "N/A"));
        contextBuilder.append(String.format("- Current Status: %s\n", context.getCurrentStatus()));
        contextBuilder.append(String.format("- Detection Source: %s\n", context.getDetectedSource()));
        contextBuilder.append(String.format("- Severity: %s\n", context.getSeverity()));
        contextBuilder.append(String.format("- Recommended Actions: %s\n", context.getRecommendedActions()));
        contextBuilder.append(String.format("- Analysis Time: %s\n\n", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)));

        if (ragContext != null && !ragContext.trim().isEmpty()) {
            contextBuilder.append("### Related Security Knowledge (RAG)\n");
            contextBuilder.append(ragContext);
            contextBuilder.append("\n\n");
        }

        contextBuilder.append("### AI Analysis Guide\n");
        contextBuilder.append("Based on the information above, evaluate the following and suggest automated actions:\n");
        contextBuilder.append("1. Re-evaluate incident severity\n");
        contextBuilder.append("2. List of playbooks or automated actions to execute\n");
        contextBuilder.append("3. Expected results of each action\n");
        contextBuilder.append("4. Final summary and next steps\n");

        return contextBuilder.toString();
    }

    private String getDefaultContext() {
        return """
                ## Default SOAR Context

                Insufficient data for SOAR analysis.
                Following basic incident response procedures.
                """;
    }
}