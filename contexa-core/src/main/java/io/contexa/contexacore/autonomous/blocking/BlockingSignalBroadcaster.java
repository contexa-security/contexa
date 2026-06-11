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
package io.contexa.contexacore.autonomous.blocking;

/**
 * Abstraction for broadcasting block/unblock signals across instances.
 * Implementations: BlockingDecisionRegistry (distributed/Redisson), InMemoryBlockingSignalBroadcaster (standalone).
 */
public interface BlockingSignalBroadcaster {

    default void registerBlock(String userId) {
        registerBlock(userId, "BLOCK");
    }

    void registerBlock(String userId, String action);

    void registerUnblock(String userId);

    boolean isBlocked(String userId);

    String getBlockAction(String userId);
}
