package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizedContextRetrieverTest {

    @Test
    void retrieveContextShouldApplyAuthorizationTraceToContextInfo() {
        VectorStore vectorStore = mock(VectorStore.class);
        when(vectorStore.similaritySearch(any(SearchRequest.class))).thenReturn(List.of(
                new Document("allowed behavior", new LinkedHashMap<>(Map.of(
                        "documentType", "behavior",
                        "userId", "user-1",
                        "organizationId", "tenant-a",
                        "allowedPurpose", "security_investigation",
                        "id", "doc-1"))),
                new Document("denied behavior", new LinkedHashMap<>(Map.of(
                        "documentType", "behavior",
                        "userId", "user-2",
                        "organizationId", "tenant-a",
                        "id", "doc-2")))));

        AuthorizedContextRetriever retriever = new AuthorizedContextRetriever(
                vectorStore,
                new ContexaRagProperties(),
                new PromptContextAuthorizationService());

        TestContext context = new TestContext();
        context.setUserId("user-1");
        context.setOrganizationId("tenant-a");

        AIRequest<TestContext> request = new AIRequest<>(context, new TemplateType("standard"), new DiagnosisType("general"));
        request.setNaturalLanguageQuery("login anomaly");
        request.withParameter("retrievalPurpose", "security_investigation");

        ContextRetriever.ContextRetrievalResult result = retriever.retrieveContext(request);

        assertThat(result.getDocuments()).hasSize(1);
        assertThat(result.getContextInfo()).contains("auth=ALLOWED_USER_SCOPE");
        assertThat(result.getContextInfo()).contains("artifact=doc-1");
        assertThat(result.getContextInfo()).contains("guard=ALLOWED_PROMPT_SAFE");
        assertThat(result.getContextInfo()).contains("memory=ALLOWED_STANDARD_CONTEXT");
        assertThat(result.getMetadata()).containsEntry("documentsAuthorized", 1);
        assertThat(result.getMetadata()).containsEntry("documentsDenied", 1);
        assertThat(result.getMetadata()).containsKey("retrievalPolicySummary");
        assertThat(result.getMetadata()).containsEntry("provenanceRecordCount", 2);
    }

    private static class TestContext extends DomainContext {
        @Override
        public String getDomainType() {
            return "test";
        }
    }
}