package io.contexa.contexacore.autonomous.service;

/**
 * Interface for recording blocked users to persistent storage.
 * Implemented in contexa-iam module to avoid reverse dependency from contexa-core.
 */
public interface IBlockedUserRecorder {

    void recordBlock(String requestId, String userId, String username,
                     String action, String reasoning,
                     String sourceIp, String userAgent);

    void resolveBlock(String userId, String adminId, String resolvedAction, String reason);

    default void markMfaVerified(String userId) {}

    default void markMfaFailed(String userId) {}
}
