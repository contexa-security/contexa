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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;

/** The narrowed scopes kept in memory; a restart forgets them. */
public class InMemoryAgentScopeStore implements AgentScopeStore {

    private final Map<String, AgentScopeRestriction> scopes = new ConcurrentHashMap<>();

    @Override
    public Optional<AgentScopeRestriction> find(String subjectKey) {
        return Optional.ofNullable(subjectKey != null ? scopes.get(subjectKey) : null);
    }

    @Override
    public AgentScopeRestriction merge(String subjectKey, Instant now, UnaryOperator<AgentScopeRestriction> narrowing) {
        return scopes.compute(subjectKey, (key, current) ->
                narrowing.apply(current != null && current.activeAt(now) ? current : null));
    }

    @Override
    public List<AgentScopeRestriction> active(Instant now, int limit) {
        scopes.values().removeIf(scope -> !scope.activeAt(now));
        return scopes.values().stream()
                .sorted(Comparator.comparing(AgentScopeRestriction::until))
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public void removeForUser(String userId) {
        if (userId != null) {
            scopes.values().removeIf(scope -> scope.userId().equals(userId));
        }
    }
}
