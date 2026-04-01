package io.contexa.contexaiam.security.xacml.pap.dto;

public record SimulationTestCase(
        Long userId,
        String targetType,
        String path,
        String httpMethod) {

    public SimulationTestCase(Long userId, String path, String httpMethod) {
        this(userId, "URL", path, httpMethod);
    }

    public String resolvedTargetType() {
        return targetType != null ? targetType : "URL";
    }
}
