package io.contexa.contexaiam.admin.web.center.dto;

import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class PolicySimulationRequest {
    private PolicyCenterPolicyRequest candidatePolicy;
    private List<TestCaseRequest> testCases = new ArrayList<>();

    public PolicyDto toCandidatePolicyDto() {
        return candidatePolicy != null ? candidatePolicy.toPolicyDto() : null;
    }

    public List<SimulationTestCase> toSimulationTestCases() {
        return testCases == null
                ? null
                : new ArrayList<>(testCases.stream().map(TestCaseRequest::toSimulationTestCase).toList());
    }

    @Data
    public static class TestCaseRequest {
        private Long userId;
        private String targetType;
        private String path;
        private String httpMethod;

        private SimulationTestCase toSimulationTestCase() {
            return new SimulationTestCase(userId, targetType, path, httpMethod);
        }
    }
}
