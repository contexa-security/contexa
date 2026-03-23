package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AuthorizedContextRetriever extends ContextRetriever {

    private final PromptContextAuthorizationService promptContextAuthorizationService;

    public AuthorizedContextRetriever(
            VectorStore vectorStore,
            ContexaRagProperties ragProperties,
            PromptContextAuthorizationService promptContextAuthorizationService) {
        super(vectorStore, ragProperties);
        this.promptContextAuthorizationService = promptContextAuthorizationService;
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
        String query = extractQueryFromRequest(request);

        SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(ragProperties.getDefaults().getTopK())
                .similarityThreshold(ragProperties.getDefaults().getSimilarityThreshold())
                .build();

        List<Document> retrievedDocuments = vectorStore.similaritySearch(searchRequest);
        AuthorizedPromptContext authorizedContext = promptContextAuthorizationService.authorize(request, retrievedDocuments);

        String contextInfo = authorizedContext.documents().stream()
                .map(this::formatAuthorizedDocument)
                .collect(Collectors.joining("\n"));

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentsFound", retrievedDocuments != null ? retrievedDocuments.size() : 0);
        metadata.put("documentsAuthorized", authorizedContext.allowedDocumentCount());
        metadata.put("documentsDenied", authorizedContext.deniedDocumentCount());
        metadata.put("searchQuery", query);
        metadata.put("retrievalPurpose", authorizedContext.retrievalPurpose());
        metadata.put("retrievalPolicySummary", authorizedContext.retrievalPolicy().summary());
        metadata.put("provenanceRecordCount", authorizedContext.provenanceRecords().size());

        return new ContextRetrievalResult(contextInfo, authorizedContext.documents(), metadata);
    }

    private String formatAuthorizedDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        String authorizationDecision = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED"));
        String accessScope = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.ACCESS_SCOPE, "GLOBAL"));
        String artifactId = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.ARTIFACT_ID, "unknown"));
        String sourceType = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.SOURCE_TYPE,
                metadata.getOrDefault(VectorDocumentMetadata.DOCUMENT_TYPE, "standard")));
        Object purposeMatch = metadata.getOrDefault(VectorDocumentMetadata.PURPOSE_MATCH, Boolean.TRUE);
        Object tenantBound = metadata.getOrDefault(VectorDocumentMetadata.TENANT_BOUND, Boolean.FALSE);
        String provenanceSummary = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.PROVENANCE_SUMMARY, "core_context"));
        String promptSafetyDecision = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.PROMPT_SAFETY_DECISION, "ALLOWED_PROMPT_SAFE"));
        String memoryReadDecision = String.valueOf(metadata.getOrDefault(VectorDocumentMetadata.MEMORY_READ_DECISION, "ALLOWED_STANDARD_CONTEXT"));
        return "- [auth=" + authorizationDecision
                + "|scope=" + accessScope
                + "|purpose=" + purposeMatch
                + "|tenantBound=" + tenantBound
                + "|artifact=" + artifactId
                + "|source=" + sourceType
                + "|guard=" + promptSafetyDecision
                + "|memory=" + memoryReadDecision
                + "|prov=" + provenanceSummary
                + "] " + document.getText();
    }
}