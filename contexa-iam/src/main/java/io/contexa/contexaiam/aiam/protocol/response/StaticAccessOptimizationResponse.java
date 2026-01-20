package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.IAMResponse;
import io.contexa.contexacommon.enums.ExecutionStatus;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;


@Getter
@Setter
public class StaticAccessOptimizationResponse extends IAMResponse {
    private OptimizationStrategy optimizationStrategy;
    private PolicyProposal policyProposal;
    private String spelExpression;
    private EffectPrediction effectPrediction;
    private double aiConfidenceScore;
    private long executionTimeMs;
    private LocalDateTime completedAt;
    private String errorMessage;
    
    public StaticAccessOptimizationResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }
    
    public static StaticAccessOptimizationResponse createSuccess(String requestId) {
        return new StaticAccessOptimizationResponse(requestId, ExecutionStatus.SUCCESS);
    }
    
    public static StaticAccessOptimizationResponse createSuccess(
            String requestId,
            PolicyProposal proposal,
            OptimizationStrategy strategy,
            EffectPrediction prediction,
            String spelExpression) {
        
        StaticAccessOptimizationResponse response = new StaticAccessOptimizationResponse(requestId, ExecutionStatus.SUCCESS);
        response.setPolicyProposal(proposal);
        response.setOptimizationStrategy(strategy);
        response.setEffectPrediction(prediction);
        response.setSpelExpression(spelExpression);
        response.setCompletedAt(LocalDateTime.now());
        return response;
    }
    
    public static StaticAccessOptimizationResponse createFailure(String requestId, String errorMessage) {
        StaticAccessOptimizationResponse response = new StaticAccessOptimizationResponse(requestId, ExecutionStatus.FAILURE);
        response.setErrorMessage(errorMessage);
        return response;
    }
    
    public static StaticAccessOptimizationResponse createError(String requestId, String errorCode, String errorMessage) {
        StaticAccessOptimizationResponse response = new StaticAccessOptimizationResponse(requestId, ExecutionStatus.FAILURE);
        response.setErrorMessage(errorCode + ": " + errorMessage);
        return response;
    }
    
    @Override
    public Object getData() {
        Map<String, Object> data = new HashMap<>();
        data.put("optimizationStrategy", optimizationStrategy);
        data.put("policyProposal", policyProposal);
        data.put("spelExpression", spelExpression);
        data.put("effectPrediction", effectPrediction);
        data.put("aiConfidenceScore", aiConfidenceScore);
        data.put("status", getStatus());
        return data;
    }
    
    @Override
    public String getResponseType() {
        return "STATIC_ACCESS_OPTIMIZATION";
    }
    
    
    @Data
    public static class OptimizationStrategy {
        private String type;
        private String principle;
        private String approach;
        private String priority;
        private String description;
    }
    
    
    @Data
    public static class PolicyProposal {
        private String proposalId;
        private String title;
        private String description;
        private String actionType;
        private String riskLevel;
        private String aiRationale;
        private String targetResource;
        private String targetUser;
        private String spelExpression;
        private String scope;
        private String policyType;
        private LocalDateTime createdAt;
        private Map<String, Object> metadata;
    }
    
    
    @Data
    public static class EffectPrediction {
        private double accessReductionRate;
        private double securityImprovement;
        private double complianceScore;
        private String userImpact;
        private String estimatedRolloutTime;
        private boolean requiresUserTraining;
        private double confidenceScore;
    }
}