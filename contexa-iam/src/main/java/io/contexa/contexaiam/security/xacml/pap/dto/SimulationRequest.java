package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexaiam.domain.dto.PolicyDto;

import java.util.List;

public record SimulationRequest(
        PolicyDto candidatePolicy,
        List<SimulationTestCase> testCases) {
}
