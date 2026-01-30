package io.contexa.contexacore.std.labs.risk;

import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import org.springframework.ai.vectorstore.VectorStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Slf4j
public class RiskAssessmentVectorService extends AbstractVectorLabService {

    @Value("${spring.ai.risk.continuous-validation:true}")
    private boolean continuousValidation;

    @Value("${spring.ai.risk.context-aware-assessment:true}")
    private boolean contextAwareAssessment;

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
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());

        try {
            List<String> riskIndicators = detectRiskIndicators(document.getText());
            metadata.put("riskIndicators", riskIndicators);
            metadata.put("riskIndicatorCount", riskIndicators.size());

            List<String> contextualFactors = detectContextualFactors(document.getText());
            metadata.put("contextualFactors", contextualFactors);

            if (contextAwareAssessment) {
                List<String> timeFactors = detectTimeBasedFactors();
                metadata.put("timeBasedFactors", timeFactors);
            }

            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "RiskAssessmentVectorService");
            metadata.put("assessmentTimestamp", LocalDateTime.now().format(ISO_FORMATTER));

            return new Document(document.getText(), metadata);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] Metadata enrichment failed", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
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
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();

            if (operationType == OperationType.STORE) {
                @SuppressWarnings("unchecked")
                List<String> riskIndicators = (List<String>) metadata.get("riskIndicators");
                if (riskIndicators != null && riskIndicators.size() > 5) {
                    metadata.put("highRiskIndicatorAlert", true);
                    metadata.put("alertTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
                }
            }

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] Post-processing failed", e);
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());

        if (continuousValidation) {
            filters.put("includeContinuousValidation", true);
        }
        if (contextAwareAssessment) {
            filters.put("includeContextAware", true);
        }

        return filters;
    }

    public void storeRiskAssessmentRequest(RiskAssessmentRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("resourceId", request.getResourceId());
            metadata.put("actionType", request.getActionType());
            metadata.put("organizationId", request.getContext().getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "risk_assessment_request");
            metadata.put("requestId", UUID.randomUUID().toString());

            metadata.put("historyAnalysisEnabled", request.isEnableHistoryAnalysis());
            metadata.put("behaviorAnalysisEnabled", request.isEnableBehaviorAnalysis());
            metadata.put("maxHistoryRecords", request.getMaxHistoryRecords());

            String requestText = String.format(
                "Risk assessment request: user=%s, resource=%s, action=%s, organization=%s, historyAnalysis=%s",
                request.getUserId(),
                request.getResourceId(),
                request.getActionType(),
                request.getContext().getOrganizationId(),
                request.isEnableHistoryAnalysis()
            );

            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] Failed to store risk assessment request", e);
            throw new VectorStoreException("Failed to store risk assessment request: " + e.getMessage(), e);
        }
    }

    public void storeRiskAssessmentResult(RiskAssessmentRequest request, RiskAssessmentResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("resourceId", request.getResourceId());
            metadata.put("actionType", request.getActionType());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "risk_assessment_result");
            metadata.put("assessmentId", response.getResponseId());

            metadata.put("trustScore", response.trustScore());
            metadata.put("riskScore", response.riskScore());
            metadata.put("riskTags", response.getAssessment() != null ? response.getAssessment().riskTags() : List.of());
            metadata.put("recommendation", response.recommendation());

            if (response.getAssessment() != null && response.getAssessment().riskTags() != null) {
                metadata.put("riskFactors", response.getAssessment().riskTags());
                metadata.put("riskFactorCount", response.getAssessment().riskTags().size());
            }

            String resultText = String.format(
                "Zero Trust risk assessment result: trustScore=%.1f, riskScore=%.1f, recommendation=%s",
                response.trustScore(),
                response.riskScore(),
                response.recommendation()
            );

            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

            storeDetailedRiskFactors(response, metadata);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] Failed to store risk assessment result", e);
            throw new VectorStoreException("Failed to store risk assessment result: " + e.getMessage(), e);
        }
    }

    private void storeDetailedRiskFactors(RiskAssessmentResponse response, Map<String, Object> baseMetadata) {
        if (response.getAssessment() != null && response.getAssessment().riskTags() != null) {
            response.getAssessment().riskTags().forEach(factor -> {
                try {
                    Map<String, Object> factorMetadata = new HashMap<>(baseMetadata);
                    factorMetadata.put("riskFactor", factor);
                    factorMetadata.put("documentType", "risk_factor_detail");

                    String factorText = String.format("Risk factor: %s", factor);

                    Document factorDoc = new Document(factorText, factorMetadata);
                    storeDocument(factorDoc);

                } catch (Exception e) {
                    log.error("Failed to store risk factor: {}", factor, e);
                }
            });
        }
    }

    private List<String> detectRiskIndicators(String content) {
        List<String> indicators = new ArrayList<>();

        if (content == null) {
            return indicators;
        }

        String lowerContent = content.toLowerCase();

        if (lowerContent.contains("identity") || lowerContent.contains("credential") || lowerContent.contains("account")) {
            indicators.add("IDENTITY_CONCERN");
        }
        if (lowerContent.contains("access") || lowerContent.contains("permission") || lowerContent.contains("authorization")) {
            indicators.add("ACCESS_CONCERN");
        }
        if (lowerContent.contains("device") || lowerContent.contains("endpoint")) {
            indicators.add("DEVICE_CONCERN");
        }
        if (lowerContent.contains("network") || lowerContent.contains("connection") || lowerContent.contains("traffic")) {
            indicators.add("NETWORK_CONCERN");
        }
        if (lowerContent.contains("data") || lowerContent.contains("information") || lowerContent.contains("content")) {
            indicators.add("DATA_CONCERN");
        }
        if (lowerContent.contains("behavior") || lowerContent.contains("activity") || lowerContent.contains("action")) {
            indicators.add("BEHAVIOR_CONCERN");
        }
        if (lowerContent.contains("compliance") || lowerContent.contains("regulation") || lowerContent.contains("policy")) {
            indicators.add("COMPLIANCE_CONCERN");
        }

        return indicators;
    }

    private List<String> detectContextualFactors(String content) {
        List<String> factors = new ArrayList<>();

        if (content == null) {
            return factors;
        }

        String lowerContent = content.toLowerCase();

        if (lowerContent.contains("unknown location") || lowerContent.contains("new location")) {
            factors.add("UNKNOWN_LOCATION");
        }
        if (lowerContent.contains("sudden") || lowerContent.contains("rapid")) {
            factors.add("SUDDEN_CHANGE");
        }
        if (lowerContent.contains("unusual") || lowerContent.contains("anomaly") || lowerContent.contains("abnormal")) {
            factors.add("UNUSUAL_PATTERN");
        }
        if (lowerContent.contains("external") || lowerContent.contains("remote")) {
            factors.add("EXTERNAL_ACCESS");
        }
        if (lowerContent.contains("high volume") || lowerContent.contains("bulk")) {
            factors.add("HIGH_VOLUME");
        }

        return factors;
    }

    private List<String> detectTimeBasedFactors() {
        List<String> factors = new ArrayList<>();

        LocalDateTime now = LocalDateTime.now();

        if (now.getHour() < 6 || now.getHour() > 22) {
            factors.add("OFF_HOURS_ACCESS");
        }

        if (now.getDayOfWeek().getValue() > 5) {
            factors.add("WEEKEND_ACCESS");
        }

        return factors;
    }

    public List<Document> findSimilarRiskPatterns(String userId, String resourceIdentifier, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "risk_assessment");
            filters.put("userId", userId);
            filters.put("resourceIdentifier", resourceIdentifier);
            filters.put("topK", topK);

            String query = String.format("Risk assessment: user=%s resource=%s", userId, resourceIdentifier);
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("Failed to search risk patterns", e);
            return List.of();
        }
    }

    public void storeRiskAssessment(RiskAssessmentContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "risk_assessment_context");
            metadata.put("userId", context.getUserId());
            metadata.put("resourceId", context.getResourceIdentifier());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            String text = String.format("Risk assessment context: user=%s, resource=%s",
                context.getUserId(), context.getResourceIdentifier());
            Document doc = new Document(text, metadata);
            storeDocument(doc);

        } catch (Exception e) {
            log.error("Failed to store risk assessment context", e);
        }
    }

    public void storeRiskResult(String requestId, String result) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "risk_assessment_result");
            metadata.put("requestId", requestId);
            metadata.put("assessmentType", "RISK_RESULT");
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            Document doc = new Document(result, metadata);
            storeDocument(doc);

        } catch (Exception e) {
            log.error("Failed to store risk assessment result", e);
        }
    }
}
