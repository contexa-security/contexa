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
package io.contexa.contexacore.std.components.event;

import io.contexa.contexacommon.enums.SecurityLevel;

import java.time.LocalDateTime;

public class RiskEvent {
    
    private final String eventType;
    private final SecurityLevel riskLevel;
    private final LocalDateTime timestamp;
    private final String description;
    
    public RiskEvent(String eventType, SecurityLevel riskLevel) {
        this(eventType, riskLevel, null);
    }
    
    public RiskEvent(String eventType, SecurityLevel riskLevel, String description) {
        this.eventType = eventType;
        this.riskLevel = riskLevel;
        this.description = description;
        this.timestamp = LocalDateTime.now();
    }

    public String getEventType() {
        return eventType;
    }
    
    public SecurityLevel getRiskLevel() {
        return riskLevel;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    
    public String getDescription() {
        return description;
    }
    
    @Override
    public String toString() {
        return String.format("RiskEvent{eventType='%s', riskLevel=%s, timestamp=%s, description='%s'}", 
                           eventType, riskLevel, timestamp, description);
    }
} 