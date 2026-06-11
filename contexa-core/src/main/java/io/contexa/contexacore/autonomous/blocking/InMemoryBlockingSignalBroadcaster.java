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

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of BlockingSignalBroadcaster for standalone mode.
 * Uses ConcurrentHashMap instead of Redisson RTopic for single-JVM deployments.
 */
public class InMemoryBlockingSignalBroadcaster implements BlockingSignalBroadcaster {

    private final ConcurrentHashMap<String, String> blockedUsers = new ConcurrentHashMap<>();

    @Override
    public void registerBlock(String userId, String action) {
        if (userId != null && !userId.isBlank()) {
            blockedUsers.put(userId, (action != null && !action.isBlank()) ? action : "BLOCK");
        }
    }

    @Override
    public void registerUnblock(String userId) {
        if (userId != null && !userId.isBlank()) {
            blockedUsers.remove(userId);
        }
    }

    @Override
    public boolean isBlocked(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return blockedUsers.containsKey(userId);
    }

    @Override
    public String getBlockAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return blockedUsers.get(userId);
    }
}
