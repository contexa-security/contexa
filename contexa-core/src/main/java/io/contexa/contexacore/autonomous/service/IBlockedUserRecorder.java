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
package io.contexa.contexacore.autonomous.service;

import java.util.List;

/**
 * Interface for recording blocked users to persistent storage.
 * Implemented in contexa-iam module to avoid reverse dependency from contexa-core.
 */
public interface IBlockedUserRecorder {

    void recordBlock(String requestId, String userId, String username,
                     String action, String reasoning,
                     String sourceIp, String userAgent);

    /**
     * Records a block with the tenant of the blocked request (docs/agent A3-3, R-01), so that what an administrator's
     * release learns goes to the user's baseline within that tenant. A recorder that keeps no tenant records the block
     * as {@link #recordBlock(String, String, String, String, String, String, String)} does.
     */
    default void recordBlock(String requestId, String userId, String username,
                             String action, String reasoning,
                             String sourceIp, String userAgent, String tenantId) {
        recordBlock(requestId, userId, username, action, reasoning, sourceIp, userAgent);
    }

    void resolveBlock(String userId, String adminId, String resolvedAction, String reason);

    /**
     * Whether the record holds a block in force for the user: the second copy of a BLOCK, read while the decision store
     * does not answer. A recorder that keeps no record knows of none.
     */
    default boolean isBlockInForce(String userId) {
        return false;
    }

    /**
     * The users whose block the record holds in force, by the same definition as {@link #isBlockInForce}: every user
     * for whom that method answers true, under the id the block was recorded with. An application that is given a name
     * writes these blocks again under the keys of its name, as the keys it had before it had one are no longer read. A
     * recorder that keeps no record knows of none.
     */
    default List<String> blocksInForce() {
        return List.of();
    }

    default void markMfaVerified(String userId) {}

    default void markMfaFailed(String userId) {}
}
