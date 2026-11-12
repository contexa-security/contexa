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
package io.contexa.contexaiam.admin.web.agent.dto;

import org.springframework.lang.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * Each agent's latest decision, as the agents page reads it by agent ID. Empty without an audit store or when the
 * decision records cannot be read.
 */
public final class LatestAgentDecisions {

    private final Map<String, String> byAgent = new HashMap<>();

    /** The decision of a record read newest first: the first one met for an agent is its latest. */
    public void meet(String agentId, @Nullable String decision) {
        byAgent.putIfAbsent(agentId, decision);
    }

    /** The agent's latest decision, or null when it has none. */
    @Nullable
    public String of(String agentId) {
        return byAgent.get(agentId);
    }
}
