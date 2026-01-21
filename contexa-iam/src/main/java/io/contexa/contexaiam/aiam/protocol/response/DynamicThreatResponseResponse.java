package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Data
@EqualsAndHashCode(callSuper = true)
public class DynamicThreatResponseResponse extends IAMResponse {

    private PolicyProposal policyProposal;

    private String strategicPrinciple;

    private String spelExpression;

    private double aiConfidenceScore;

    private PolicyEffectPrediction effectPrediction;

    private ProcessingMetadata processingMetadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PolicyProposal {
        private String proposalId;
        private String title;
        private String description;
        private String policyType;          
        private String actionType;           
        private String scope;                
        private Integer priority;
        private String aiRationale;          
        private Map<String, Object> policyContent;  
        private LocalDateTime createdAt;
        private Boolean requiresApproval;
        private String riskLevel;            
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PolicyEffectPrediction {
        private Double threatReductionRate;     
        private Double falsePositiveRate;       
        private Double performanceImpact;       
        private Integer estimatedAffectedUsers; 
        private String impactDescription;       
        private Double confidenceScore;         
        private LocalDateTime predictionTimestamp; 
        private String modelVersion;           
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProcessingMetadata {
        private String labName;
        private String labVersion;
        private Long processingTimeMs;
        private String llmModel;
        private Integer tokenUsage;
        private Map<String, Object> additionalInfo;
    }

    public DynamicThreatResponseResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }

    public DynamicThreatResponseResponse() {
        super("", ExecutionStatus.SUCCESS);
    }
    
    @Override
    public String getResponseType() {
        return "DYNAMIC_THREAT_RESPONSE";
    }
    
    @Override
    public Object getData() {
        Map<String, Object> data = new HashMap<>();
        data.put("policyProposal", policyProposal);
        data.put("strategicPrinciple", strategicPrinciple);
        data.put("spelExpression", spelExpression);
        data.put("effectPrediction", effectPrediction);
        return data;
    }

    public static DynamicThreatResponseResponse createSuccess(
            String requestId,
            PolicyProposal proposal,
            String strategicPrinciple,
            String spelExpression,
            Double confidenceScore) {
        
        DynamicThreatResponseResponse response = new DynamicThreatResponseResponse(
                requestId, 
                ExecutionStatus.SUCCESS
        );
        
        response.setPolicyProposal(proposal);
        response.setStrategicPrinciple(strategicPrinciple);
        response.setSpelExpression(spelExpression);
        response.setAiConfidenceScore(confidenceScore != null ? confidenceScore : 0.0);
        
        return response;
    }

    public static DynamicThreatResponseResponse createFailure(
            String requestId,
            String errorMessage) {
        
        DynamicThreatResponseResponse response = new DynamicThreatResponseResponse(
                requestId, 
                ExecutionStatus.FAILURE
        );

        return response;
    }

    public boolean isValidProposal() {
        return policyProposal != null &&
               policyProposal.getTitle() != null &&
               policyProposal.getPolicyContent() != null &&
               getAiConfidenceScore() >= 0.5;
    }

    public boolean isHighRiskPolicy() {
        return policyProposal != null &&
               ("HIGH".equals(policyProposal.getRiskLevel()) || 
                "CRITICAL".equals(policyProposal.getRiskLevel()));
    }
}