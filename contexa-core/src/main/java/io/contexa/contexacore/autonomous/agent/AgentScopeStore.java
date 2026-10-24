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
package io.contexa.contexacore.autonomous.agent;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Where the narrowed scopes of agents are kept (docs/agent A5-4), one per agent decision key. Contexa keeps them in
 * memory by default and in its database with the console.
 */
public interface AgentScopeStore {

    Optional<AgentScopeRestriction> find(String subjectKey);

    /**
     * Applies a narrowing to the scope kept under the key, atomically: the function gets the scope in force (null
     * for none or an ended one) and returns the scope to keep.
     *
     * @return the scope kept
     */
    AgentScopeRestriction merge(String subjectKey, Instant now, UnaryOperator<AgentScopeRestriction> narrowing);

    /** The scopes still in force at {@code now}, the latest ending last. */
    List<AgentScopeRestriction> active(Instant now, int limit);

    /** Forgets the scopes of the agents acting for the user (the user's account was deleted). */
    void removeForUser(String userId);
}
