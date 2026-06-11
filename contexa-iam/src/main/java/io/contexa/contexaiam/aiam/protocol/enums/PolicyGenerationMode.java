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
package io.contexa.contexaiam.aiam.protocol.enums;

public enum PolicyGenerationMode {
    
    QUICK("Quick Generation", "Rapid policy generation using basic templates"),

    AI_ASSISTED("AI-Assisted Generation", "Policy generation mode with active AI assistance"),

    PRECISE("Precise Generation", "Precise policy generation through full AI analysis"),

    EXPERIMENTAL("Experimental Generation", "Experimental policy generation applying latest AI techniques");
    
    private final String displayName;
    private final String description;
    
    PolicyGenerationMode(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
} 