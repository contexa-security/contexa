package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class SecurityCopilotResponse extends IAMResponse {

    private String analysisId;

    private String originalQuery;

    private Object structureAnalysis;

    private Object riskAnalysis;

    private Object actionPlan;

    private double overallSecurityScore;

    private String riskLevel;

    private Map<String, Double> categoryScores;

    private Map<String, Object> complianceData;

    private long executionTimeMs;

    private Map<String, String> errors;

    private Map<String, Object> metadata;

    private List<Object> criticalFindings;

    private List<Object> recommendations;

    private String complianceStatus;

    private ThreatAnalysis threatAnalysis;

    private VulnerabilityAssessment vulnerabilityAssessment;

    private Map<String, Object> individualResults;

    @Getter
    @Setter
    public static class ThreatAnalysis {
        private List<String> identifiedThreats;
        private String threatLevel;
        private List<String> attackVectors;
    }

    @Getter
    @Setter
    public static class VulnerabilityAssessment {
        private List<Object> vulnerabilities;
        private int criticalCount;
        private int patchableCount;
        
        public List<Object> getVulnerabilities() {
            return vulnerabilities;
        }
        
        public int getCriticalCount() {
            return criticalCount;
        }
        
        public int getPatchableCount() {
            return patchableCount;
        }
    }

    private Map<String, Object> relationshipAnalysis;

    private Map<String, Object> integratedVisualizationData;

    private Map<String, Object> multiPerspectiveInsights;

    private List<Map<String, Object>> actionPriorities;

    private Map<String, Object> predictiveAnalysis;

    private java.time.LocalDateTime completedAt;

    private String recommendationSummary;

    public SecurityCopilotResponse() {
        super("default", ExecutionStatus.SUCCESS);
    }
    
    public SecurityCopilotResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }
    
    public SecurityCopilotResponse(String requestId, ExecutionStatus status, String recommendationSummary) {
        super(requestId, status);
        this.recommendationSummary = recommendationSummary;
    }

    @Override
    public Object getData() {
        
        return recommendationSummary != null ? recommendationSummary : "보안 분석 완료";
    }
    
    @Override
    public String getResponseType() {
        return "SECURITY_COPILOT";
    }

    public static SecurityCopilotResponseBuilder builder() {
        return new SecurityCopilotResponseBuilder();
    }
    
    public SecurityCopilotResponseBuilder toBuilder() {
        return new SecurityCopilotResponseBuilder(this);
    }
    
    public static class SecurityCopilotResponseBuilder {
        private String requestId = "default";
        private ExecutionStatus status = ExecutionStatus.SUCCESS;
        private String analysisId;
        private String originalQuery;
        private Object structureAnalysis;
        private Object riskAnalysis;
        private Object actionPlan;
        private double overallSecurityScore;
        private String riskLevel;
        private Map<String, Double> categoryScores;
        private Map<String, Object> complianceData;
        private long executionTimeMs;
        private Map<String, String> errors;
        private Map<String, Object> metadata;
        private Map<String, Object> relationshipAnalysis;
        private Map<String, Object> integratedVisualizationData;
        private Map<String, Object> multiPerspectiveInsights;
        private List<Map<String, Object>> actionPriorities;
        private Map<String, Object> predictiveAnalysis;
        private java.time.LocalDateTime completedAt;
        private String recommendationSummary;
        
        public SecurityCopilotResponseBuilder() {
        }
        
        public SecurityCopilotResponseBuilder(SecurityCopilotResponse existing) {
            this.requestId = existing.getResponseId();
            this.status = existing.getStatus();
            this.analysisId = existing.analysisId;
            this.originalQuery = existing.originalQuery;
            this.structureAnalysis = existing.structureAnalysis;
            this.riskAnalysis = existing.riskAnalysis;
            this.actionPlan = existing.actionPlan;
            this.overallSecurityScore = existing.overallSecurityScore;
            this.riskLevel = existing.riskLevel;
            this.categoryScores = existing.categoryScores;
            this.complianceData = existing.complianceData;
            this.executionTimeMs = existing.executionTimeMs;
            this.errors = existing.errors;
            this.metadata = existing.metadata;
            this.relationshipAnalysis = existing.relationshipAnalysis;
            this.integratedVisualizationData = existing.integratedVisualizationData;
            this.multiPerspectiveInsights = existing.multiPerspectiveInsights;
            this.actionPriorities = existing.actionPriorities;
            this.predictiveAnalysis = existing.predictiveAnalysis;
            this.completedAt = existing.completedAt;
            this.recommendationSummary = existing.recommendationSummary;
        }
        
        public SecurityCopilotResponseBuilder analysisId(String analysisId) {
            this.analysisId = analysisId;
            return this;
        }
        
        public SecurityCopilotResponseBuilder recommendationSummary(String recommendationSummary) {
            this.recommendationSummary = recommendationSummary;
            return this;
        }
        
        public SecurityCopilotResponseBuilder overallSecurityScore(double overallSecurityScore) {
            this.overallSecurityScore = overallSecurityScore;
            return this;
        }
        
        public SecurityCopilotResponseBuilder riskLevel(String riskLevel) {
            this.riskLevel = riskLevel;
            return this;
        }
        
        public SecurityCopilotResponseBuilder categoryScores(Map<String, Double> categoryScores) {
            this.categoryScores = categoryScores;
            return this;
        }
        
        public SecurityCopilotResponseBuilder complianceData(Map<String, Object> complianceData) {
            this.complianceData = complianceData;
            return this;
        }

        public SecurityCopilotResponseBuilder originalQuery(String originalQuery) {
            this.originalQuery = originalQuery;
            return this;
        }

        public SecurityCopilotResponseBuilder status(String status) {
            
            if ("COMPLETED".equals(status)) {
                this.status = ExecutionStatus.SUCCESS;
            } else if ("FAILED".equals(status)) {
                this.status = ExecutionStatus.FAILURE;
            } else if ("PARTIAL".equals(status)) {
                this.status = ExecutionStatus.PARTIAL_SUCCESS;
            } else {
                this.status = ExecutionStatus.SUCCESS;
            }
            return this;
        }
        
        public SecurityCopilotResponseBuilder executionTimeMs(long executionTimeMs) {
            this.executionTimeMs = executionTimeMs;
            return this;
        }
        
        public SecurityCopilotResponseBuilder errors(Map<String, String> errors) {
            this.errors = errors;
            return this;
        }
        
        public SecurityCopilotResponseBuilder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }
        
        public SecurityCopilotResponseBuilder completedAt(java.time.LocalDateTime completedAt) {
            this.completedAt = completedAt;
            return this;
        }
        
        public SecurityCopilotResponseBuilder relationshipAnalysis(Map<String, Object> relationshipAnalysis) {
            this.relationshipAnalysis = relationshipAnalysis;
            return this;
        }
        
        public SecurityCopilotResponseBuilder integratedVisualizationData(Map<String, Object> integratedVisualizationData) {
            this.integratedVisualizationData = integratedVisualizationData;
            return this;
        }
        
        public SecurityCopilotResponseBuilder multiPerspectiveInsights(Map<String, Object> multiPerspectiveInsights) {
            this.multiPerspectiveInsights = multiPerspectiveInsights;
            return this;
        }
        
        public SecurityCopilotResponseBuilder actionPriorities(List<Map<String, Object>> actionPriorities) {
            this.actionPriorities = actionPriorities;
            return this;
        }
        
        public SecurityCopilotResponseBuilder predictiveAnalysis(Map<String, Object> predictiveAnalysis) {
            this.predictiveAnalysis = predictiveAnalysis;
            return this;
        }
        
        public SecurityCopilotResponse build() {
            SecurityCopilotResponse response = new SecurityCopilotResponse(this.requestId, this.status, this.recommendationSummary);
            response.analysisId = this.analysisId;
            response.originalQuery = this.originalQuery;
            response.structureAnalysis = this.structureAnalysis;
            response.riskAnalysis = this.riskAnalysis;
            response.actionPlan = this.actionPlan;
            response.overallSecurityScore = this.overallSecurityScore;
            response.riskLevel = this.riskLevel;
            response.categoryScores = this.categoryScores;
            response.complianceData = this.complianceData;
            response.executionTimeMs = this.executionTimeMs;
            response.errors = this.errors;
            response.metadata = this.metadata;
            response.relationshipAnalysis = this.relationshipAnalysis;
            response.integratedVisualizationData = this.integratedVisualizationData;
            response.multiPerspectiveInsights = this.multiPerspectiveInsights;
            response.actionPriorities = this.actionPriorities;
            response.predictiveAnalysis = this.predictiveAnalysis;
            response.completedAt = this.completedAt;
            return response;
        }
    }

    public boolean isSuccessful() {
        ExecutionStatus status = getStatus();
        return status == ExecutionStatus.SUCCESS || status == ExecutionStatus.PARTIAL_SUCCESS;
    }

    public boolean hasErrors() {
        return errors != null && !errors.isEmpty();
    }

    public String getRiskLevel() {
        
        if (riskLevel != null) {
            return riskLevel;
        }

        if (overallSecurityScore >= 80) return "LOW";
        if (overallSecurityScore >= 60) return "MEDIUM";
        if (overallSecurityScore >= 40) return "HIGH";
        return "CRITICAL";
    }

    public Map<String, Double> getCategoryScores() {
        
        if (categoryScores != null) {
            return categoryScores;
        }

        if (metadata != null && metadata.containsKey("categoryScores")) {
            @SuppressWarnings("unchecked")
            Map<String, Double> metadataScores = (Map<String, Double>) metadata.get("categoryScores");
            return metadataScores;
        }
        
        return new java.util.HashMap<>();
    }

    public Map<String, Object> getComplianceData() {
        
        if (complianceData != null) {
            return complianceData;
        }

        if (metadata != null && metadata.containsKey("complianceStatus")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadataCompliance = (Map<String, Object>) metadata.get("complianceStatus");
            return metadataCompliance;
        }
        
        return new java.util.HashMap<>();
    }
} 