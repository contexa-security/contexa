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


public enum SecurityLevel {
    
    MINIMAL(1, "Minimal Security", "Basic security level suitable for dev/test environments"),
    
    
    STANDARD(2, "Standard Security", "Standard security level suitable for general operational environments"),
    
    
    ENHANCED(3, "Enhanced Security", "Enhanced security level for critical systems and data"),
    
    
    HIGH(4, "High Security", "High security level for core data and critical operations"),
    
    
    MAXIMUM(5, "Maximum Security", "Maximum security level for core infrastructure and top-secret data");

    private final int level;
    private final String displayName;
    private final String description;
    
    SecurityLevel(int level, String displayName, String description) {
        this.level = level;
        this.displayName = displayName;
        this.description = description;
    }
    
    
    public int getLevel() {
        return level;
    }
    
    
    public String getDisplayName() {
        return displayName;
    }
    
    
    public String getDescription() {
        return description;
    }
    
    
    public boolean meetsRequirement(SecurityLevel requiredLevel) {
        return this.level >= requiredLevel.level;
    }
} 