package io.contexa.contexacommon.mcp.permit;

public record PermitValidationResponse(
        boolean allowed,
        String permitId,
        String reason,
        String toolName,
        String requiredScope,
        String requestId,
        String approvalId,
        String incidentId,
        String sessionId,
        String executionClass,
        String argumentsHash,
        String tenantId,
        String userId,
        String zeroTrustAction,
        Double riskScore,
        Double confidence,
        String contextBindingHashDigest,
        String actorType,
        String executionMode,
        String riskLevel) {

    public static PermitValidationResponse allowed(
            String permitId,
            String toolName,
            String requiredScope,
            String requestId,
            String approvalId,
            String incidentId,
            String sessionId,
            String executionClass,
            String argumentsHash,
            String tenantId,
            String userId,
            String zeroTrustAction,
            Double riskScore,
            Double confidence,
            String contextBindingHashDigest,
            String actorType,
            String executionMode,
            String riskLevel) {
        return new PermitValidationResponse(
                true,
                permitId,
                null,
                toolName,
                requiredScope,
                requestId,
                approvalId,
                incidentId,
                sessionId,
                executionClass,
                argumentsHash,
                tenantId,
                userId,
                zeroTrustAction,
                riskScore,
                confidence,
                contextBindingHashDigest,
                actorType,
                executionMode,
                riskLevel
        );
    }

    public static PermitValidationResponse denied(String reason) {
        return new PermitValidationResponse(
                false,
                null,
                reason,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}