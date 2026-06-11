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
package io.contexa.contexacore.autonomous.tiered.routing;

public enum ProcessingMode {

    REALTIME_BLOCK,

    AI_ANALYSIS,

    SOAR_ORCHESTRATION,

    AWAIT_APPROVAL;

    public boolean isRealtime() {
        return this == REALTIME_BLOCK;
    }

    public boolean isBlocking() {
        return this == REALTIME_BLOCK;
    }

    public boolean needsEscalation() {
        return this == SOAR_ORCHESTRATION;
    }

    public boolean needsMonitoring() {
        return this == AI_ANALYSIS;
    }

    public boolean needsHumanIntervention() {
        return this == AWAIT_APPROVAL;
    }
}