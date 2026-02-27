package io.contexa.contexacore.autonomous.service;

/**
 * Interface for force-logout operations without HTTP context.
 * Implemented in contexa-identity module to avoid reverse dependency from contexa-core.
 */
public interface IForceLogoutService {

    void forceLogoutByUserId(String userId, String reason);
}
