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
package io.contexa.contexacore.autonomous.store;

import org.springframework.lang.Nullable;

import java.time.Instant;

public interface BlockMfaStateStore {

    void setVerified(String userId);

    boolean isVerified(String userId);

    /**
     * Keeps the verification for the context that passed it, the one the client goes on in, as an ALLOW after a CHALLENGE
     * is kept: it answers for that session and for no other of the account. The last context that passed takes the place
     * of the one before.
     */
    default void setVerified(String userId, @Nullable String contextBindingHash) {
        setVerified(userId);
    }

    /**
     * Whether the given context passed the verification in force. A store that keeps no context answers false, and the
     * BLOCK stays with another administrator.
     */
    default boolean isVerified(String userId, @Nullable String contextBindingHash) {
        return false;
    }

    default Instant getVerifiedAt(String userId) {
        return null;
    }

    default Instant getVerifiedExpiresAt(String userId) {
        return null;
    }

    void setPending(String userId);

    void clearPending(String userId);

    int getFailCount(String userId);

    /** Removes the BLOCK MFA state of a user whose account is deleted. */
    default void clearUser(String userId) {
        throw new UnsupportedOperationException(
                "BLOCK MFA state deletion is not supported by " + getClass().getSimpleName());
    }
}
