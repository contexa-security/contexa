package io.contexa.contexacommon.mcp.permit;

public record PermitRevokeResponse(
        boolean revoked,
        String permitId,
        String status,
        String reason) {

    public static PermitRevokeResponse revoked(String permitId, String status) {
        return new PermitRevokeResponse(true, permitId, status, null);
    }

    public static PermitRevokeResponse rejected(String permitId, String reason) {
        return new PermitRevokeResponse(false, permitId, null, reason);
    }
}