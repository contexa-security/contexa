package io.contexa.contexacommon.mcp.permit;

import java.time.LocalDateTime;
import java.util.Map;

public record PermitIssueRequest(
        String requestId,
        String permitId,
        String approvalId,
        String incidentId,
        String sessionId,
        String tenantId,
        String userId,
        String toolName,
        String requiredScope,
        String executionClass,
        String argumentsHash,
        String riskLevel,
        Double riskScore,
        Double confidence,
        String zeroTrustAction,
        String contextBindingHash,
        String actorType,
        String executionMode,
        LocalDateTime expiresAt,
        Map<String, Object> metadata) {
}