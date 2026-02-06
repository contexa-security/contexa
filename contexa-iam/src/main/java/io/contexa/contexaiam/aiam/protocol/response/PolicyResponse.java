package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class PolicyResponse extends AIResponse {
    
    private String generatedPolicy;

    private BusinessPolicyDto policyData;
    private Map<String, String> roleIdToNameMap;
    private Map<String, String> permissionIdToNameMap;
    private Map<String, String> conditionIdToNameMap;

    public PolicyResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }
}