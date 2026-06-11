/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

    /** Legacy entrypoint kept for backward compatibility. Delegates to {@link #onLoginFailure(String, String, String,String)}. */
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
