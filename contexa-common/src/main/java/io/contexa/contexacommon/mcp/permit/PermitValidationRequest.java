package io.contexa.contexacommon.mcp.permit;

public record PermitValidationRequest(
        String permitId,
        String toolName,
        String requiredScope,
        String executionClass,
        String requestId,
        String approvalId,
        String incidentId,
        String sessionId,
        String argumentsHash,
        String riskLevel,
        String tenantId,
        String userId,
        String zeroTrustAction,
        String contextBindingHashDigest,
        String actorType,
        String executionMode) {
}