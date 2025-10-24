package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * 정책 관련 응답 클래스
 * 정책 생성, 최적화, 검증 결과를 담는 응답
 */
@Getter
@Setter
public class PolicyResponse extends IAMResponse {
    
    private String generatedPolicy;
    private Double policyConfidenceScore;
    private List<String> appliedRules;
    private String policyFormat;
    private boolean optimized;
    
    private BusinessPolicyDto policyData;
    private Map<String, String> roleIdToNameMap;
    private Map<String, String> permissionIdToNameMap;
    private Map<String, String> conditionIdToNameMap;
    
    public PolicyResponse() {
        super("default", ExecutionStatus.SUCCESS);
    }
    
    public PolicyResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }
    
    public PolicyResponse(String requestId, ExecutionStatus status, String generatedPolicy) {
        super(requestId, status);
        this.generatedPolicy = generatedPolicy;
    }
    
    @Override
    public Object getData() { 
        return policyData != null ? policyData : generatedPolicy; 
    }
    
    @Override
    public String getResponseType() { 
        return "POLICY"; 
    }

    @Override
    public String toString() {
        return String.format("PolicyResponse{status=%s, confidence=%.2f, optimized=%s, hasPolicyData=%s}", 
                getStatus(), policyConfidenceScore != null ? policyConfidenceScore : 0.0, optimized, policyData != null);
    }
} 