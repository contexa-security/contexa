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
import java.util.Map;

/**
 * Outcome of {@link UserEngineStatePurger#purge(String)}.
 *
 * @param userId       the purged user
 * @param purgedSteps  steps that completed, in execution order
 * @param failedSteps  step name to failure message for the steps that did not complete
 */
public record UserEngineStatePurgeResult(String userId, List<String> purgedSteps, Map<String, String> failedSteps) {

    public UserEngineStatePurgeResult {
        purgedSteps = List.copyOf(purgedSteps);
        failedSteps = Map.copyOf(failedSteps);
    }

    public boolean complete() {
        return failedSteps.isEmpty();
    }
}
