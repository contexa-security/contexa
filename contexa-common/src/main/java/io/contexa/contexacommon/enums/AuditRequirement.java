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
package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum AuditRequirement {
    
    NONE("NONE", "Skip audit logging in dev/test environments"),
    
    
    BASIC("BASIC", "Log only basic actions"),
    
    
    DETAILED("DETAILED", "Log all detailed actions and results"),
    
    
    COMPREHENSIVE("COMPREHENSIVE", "Include all data, tracing info, and performance metrics"),
    
    
    REQUIRED("REQUIRED", "Mandatory audit logging per security requirements");
    
    private final String displayName;
    private final String description;
    
    AuditRequirement(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    public boolean isAuditRequired() {
        return this != NONE;
    }
} 