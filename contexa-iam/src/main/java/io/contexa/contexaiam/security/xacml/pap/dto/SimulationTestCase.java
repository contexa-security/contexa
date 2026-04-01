package io.contexa.contexaiam.security.xacml.pap.dto;

public record SimulationTestCase(
        Long userId,
        String path,
        String httpMethod) {
}
