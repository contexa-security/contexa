package io.contexa.contexacore.std.labs.risk;

import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import org.springframework.ai.vectorstore.VectorStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class RiskAssessmentVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public RiskAssessmentVectorService(VectorStore vectorStore,
                                      @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }

    @Override
    protected String getLabName() {
        return "RiskAssessment";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.RISK_ASSESSMENT.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        return document;
    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("userId") &&
            !metadata.containsKey("resourceId") &&
            !metadata.containsKey("assessmentType")) {
            throw new IllegalArgumentException(
                "Risk Assessment document requires at least one of: userId, resourceId, assessmentType");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("Risk assessment content too short (minimum 10 characters required)");
        }

        if (text.length() > 10000) {
            throw new IllegalArgumentException("Risk assessment content too long (maximum 10000 characters)");
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public void storeRiskAssessmentRequest(RiskAssessmentRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("resourceId", request.getResourceId());
            metadata.put("actionType", request.getActionType());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.RISK_ASSESSMENT_REQUEST.getValue());

            String requestText = String.format(
                "Risk assessment request: user=%s, resource=%s, action=%s",
                request.getUserId(),
                request.getResourceId(),
                request.getActionType()
            );

            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] Risk assessment request storage failed", e);
            throw new VectorStoreException("Risk assessment request storage failed: " + e.getMessage(), e);
        }
    }

    public void storeRiskAssessmentResult(RiskAssessmentRequest request, RiskAssessmentResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("resourceId", request.getResourceId());
            metadata.put("actionType", request.getActionType());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", VectorDocumentType.RISK_ASSESSMENT_RESULT.getValue());

            metadata.put("trustScore", response.trustScore());
            metadata.put("riskScore", response.riskScore());

            String resultText = String.format(
                "Zero Trust risk assessment result: trustScore=%.1f, riskScore=%.1f, recommendation=%s",
                response.trustScore(),
                response.riskScore(),
                response.recommendation()
            );

            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] Risk assessment result storage failed", e);
            throw new VectorStoreException("Risk assessment result storage failed: " + e.getMessage(), e);
        }
    }

    public List<Document> findSimilarRiskPatterns(String userId, String resourceId, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("userId", userId);
            filters.put("resourceId", resourceId);
            filters.put("topK", topK);

            String query = String.format("Risk assessment: user=%s resource=%s", userId, resourceId);
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("Risk pattern search failed", e);
            return List.of();
        }
    }
}
