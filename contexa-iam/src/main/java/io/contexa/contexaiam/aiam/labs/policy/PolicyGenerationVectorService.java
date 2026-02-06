package io.contexa.contexaiam.aiam.labs.policy;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class PolicyGenerationVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public PolicyGenerationVectorService(VectorStore vectorStore,
                                        @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }

    @Override
    protected String getLabName() {
        return "PolicyGeneration";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.POLICY_GENERATION.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        return document;
    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("organizationId") &&
            !metadata.containsKey("policyName") &&
            !metadata.containsKey("naturalLanguageQuery")) {
            throw new IllegalArgumentException(
                "Policy Generation document must contain at least one of: organizationId, policyName, naturalLanguageQuery");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("Policy content is too short (minimum 10 characters required)");
        }

        if (text.length() > 10000) {
            throw new IllegalArgumentException("Policy content is too long (maximum 10000 characters)");
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public void storePolicyGenerationRequest(PolicyGenerationRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("naturalLanguageQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.POLICY_GENERATION_REQUEST.getValue());
            metadata.put("requestId", UUID.randomUUID().toString());

            String requestText = String.format(
                "Policy generation request: '%s'",
                request.getNaturalLanguageQuery()
            );

            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] Policy generation request storage failed", e);
            throw new VectorStoreException("Policy generation request storage failed: " + e.getMessage(), e);
        }
    }

    public void storeGeneratedPolicy(PolicyGenerationRequest request, PolicyResponse policyDto) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("originalQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.GENERATED_POLICY.getValue());
            metadata.put("policyId", UUID.randomUUID().toString());

            BusinessPolicyDto policy = policyDto.getPolicyData();
            if (policy != null) {
                metadata.put("policyName", policy.getPolicyName());
                metadata.put("policyDescription", policy.getDescription());
                metadata.put("roleCount", policy.getRoleIds() != null ? policy.getRoleIds().size() : 0);
                metadata.put("permissionCount", policy.getPermissionIds() != null ? policy.getPermissionIds().size() : 0);
            }

            String policyText = String.format(
                "AI generated policy: '%s' - %s (roles=%d, permissions=%d)",
                policy != null ? policy.getPolicyName() : "Unknown",
                policy != null ? policy.getDescription() : "No description",
                metadata.get("roleCount"),
                metadata.get("permissionCount")
            );

            Document policyDoc = new Document(policyText, metadata);
            storeDocument(policyDoc);

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] AI generated policy storage failed", e);
            throw new VectorStoreException("AI generated policy storage failed: " + e.getMessage(), e);
        }
    }

    public List<Document> findSimilarPolicies(String query, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("topK", topK);
        return searchSimilar(query, filters);
    }
}
