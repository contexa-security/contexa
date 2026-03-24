package io.contexa.contexacommon.security;

/**
 * Interface for login policy enforcement.
 * Tracks login success/failure and manages account lockout.
 */
public interface LoginPolicyHandler {

    void onLoginSuccess(String username, String ip);

    void onLoginFailure(String username);

    boolean checkAndUnlockIfExpired(String username);

    boolean isCredentialsExpired(String username);
}
