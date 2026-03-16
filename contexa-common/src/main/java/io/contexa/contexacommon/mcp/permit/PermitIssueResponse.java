package io.contexa.contexacommon.mcp.permit;

public record PermitIssueResponse(
        boolean issued,
        String permitId,
        String status,
        String reason) {

    public static PermitIssueResponse issued(String permitId, String status) {
        return new PermitIssueResponse(true, permitId, status, null);
    }

    public static PermitIssueResponse rejected(String reason) {
        return new PermitIssueResponse(false, null, null, reason);
    }
}