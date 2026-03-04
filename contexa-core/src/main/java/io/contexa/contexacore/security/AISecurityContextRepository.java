package io.contexa.contexacore.security;

/**
 * Common interface for AI-enhanced SecurityContextRepository implementations.
 * Provides Zero Trust session invalidation across session-based and token-based modes.
 *
 * @see AISessionSecurityContextRepository
 * @see AIOAuth2SecurityContextRepository
 */
public interface AISecurityContextRepository {

    void invalidateAllUserSessions(String userId, String reason);
}
