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

import java.util.HashMap;
import java.util.Map;

/**
 * docs/agent A5-2 (AM-1): how many delegations of people hold for each agent now, as the agents page reads it by agent
 * ID. Empty when the delegations cannot be read.
 */
public final class ActiveDelegationCounts {

    private final Map<String, Integer> byAgent = new HashMap<>();

    /** Counts one delegation that holds for the agent. */
    public void count(String agentId) {
        byAgent.merge(agentId, 1, Integer::sum);
    }

    /** The delegations that hold for the agent now; 0 when none does. */
    public int of(String agentId) {
        return byAgent.getOrDefault(agentId, 0);
    }
}
