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

/**
 * In-memory store whose entries expire. Reads already ignore expired entries; {@link #removeExpiredEntries()} also
 * releases their memory, and {@link InMemoryStateSweeper} calls it periodically in standalone mode.
 */
public interface ExpiringStateStore {

    /** Removes entries that no read can return any more. Must be safe against concurrent writers. */
    void removeExpiredEntries();
}
