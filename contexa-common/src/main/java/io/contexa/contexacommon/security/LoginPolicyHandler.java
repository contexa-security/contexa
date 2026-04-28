package io.contexa.contexacommon.security;

/**
 * Interface for login policy enforcement.
 * Tracks login success/failure and manages account lockout.
 *
 * <p>Implementations must be idempotent for a single request (a request that goes through
 * both an authentication-event listener and a legacy success/failure handler must result in
 * exactly ONE counter increment / reset).</p>
 */
public interface LoginPolicyHandler {

    /** Legacy entrypoint kept for backward compatibility. Delegates to {@link #onLoginSuccess(String, String, String)}. */
    void onLoginSuccess(String username, String ip);

    /** Legacy entrypoint kept for backward compatibility. Delegates to {@link #onLoginFailure(String, String, String)}. */
    void onLoginFailure(String username);

    /**
     * Records a successful login. Resets per-username counters and lock state atomically.
     * @param sourceTag short identifier of the caller (e.g., "HANDLER", "EVENT") for diagnostics
     */
    default void onLoginSuccess(String username, String ip, String sourceTag) {
        onLoginSuccess(username, ip);
    }

    /**
     * Records a failed login. Atomically increments per-username and per-IP counters
     * and locks when thresholds are crossed.
     * @param failureType the simple class name of the AuthenticationException (or "UNKNOWN")
     * @param sourceTag short identifier of the caller (e.g., "HANDLER", "EVENT") for diagnostics
     */
    default void onLoginFailure(String username, String ip, String failureType, String sourceTag) {
        onLoginFailure(username);
    }

    boolean checkAndUnlockIfExpired(String username);

    boolean isCredentialsExpired(String username);

    /**
     * Returns true when the IP is currently blocked by IP-dimension throttling.
     * Default implementation returns false to preserve legacy behavior.
     */
    default boolean isIpBlocked(String ip) {
        return false;
    }
}