package io.contexa.contexaiam.aiam.labs.condition;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class ConditionTemplateVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public ConditionTemplateVectorService(VectorStore vectorStore,
                                         @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }

    @Override
    protected String getLabName() {
        return "ConditionTemplate";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.CONDITION_TEMPLATE.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        return document;
    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("templateName") &&
            !metadata.containsKey("spelTemplate") &&
            !metadata.containsKey("templateType")) {
            throw new IllegalArgumentException(
                "Condition Template document must contain at least one of: templateName, spelTemplate, templateType");
        }

        String text = document.getText();
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("Condition template content is empty");
        }

        if (text.length() > 1000) {
            throw new IllegalArgumentException("Condition template content is too long (maximum 1000 characters)");
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public void storeTemplateGenerationRequest(ConditionTemplateGenerationRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.CONDITION_TEMPLATE_REQUEST.getValue());
            metadata.put("requestId", UUID.randomUUID().toString());

            String requestText = String.format(
                "Condition template generation request: type=%s, resource=%s, method=%s",
                request.isUniversal() ? "universal" : "specific",
                request.getResourceIdentifier() != null ? request.getResourceIdentifier() : "N/A",
                request.getMethodInfo() != null ? request.getMethodInfo() : "N/A"
            );

            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] Template generation request storage failed", e);
            throw new VectorStoreException("Template generation request storage failed: " + e.getMessage(), e);
        }
    }

    public void storeGeneratedTemplates(ConditionTemplateGenerationRequest request,
                                       ConditionTemplateGenerationResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("templateType", request.isUniversal() ? "universal" : "specific");
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.GENERATED_TEMPLATE.getValue());

            String resultText = String.format(
                "Condition template generation result: type=%s",
                metadata.get("templateType")
            );

            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] Generated template storage failed", e);
            throw new VectorStoreException("Generated template storage failed: " + e.getMessage(), e);
        }
    }

    public List<Document> findMethodConditions(String methodName, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("topK", topK);

            String query = String.format("Method conditions: %s", methodName);
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("Method condition search failed", e);
            return List.of();
        }
    }
}
