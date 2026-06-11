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
package io.contexa.contexacore.domain;

public enum SessionState {
    NEW("New"),
    INITIALIZED("Initialized"),
    ACTIVE("Active"),
    ANALYZING("Analyzing"),
    INVESTIGATING("Investigating"),
    WAITING_APPROVAL("Waiting Approval"),
    AWAITING_APPROVAL("Awaiting Approval"),
    CONFIRMED("Confirmed"),
    APPROVED("Approved"),
    EXECUTING("Executing"),
    COMPLETED("Completed"),
    FAILED("Failed"),
    ERROR("Error");
    
    private final String description;
    
    SessionState(String description) {
        this.description = description;
    }
    
    public String getDescription() {
        return description;
    }
}