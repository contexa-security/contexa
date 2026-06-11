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
public enum RequestPriority {
    LOW("Low", 1),
    NORMAL("Normal", 2),
    HIGH("High", 3),
    URGENT("Urgent", 4),
    CRITICAL("Critical", 5);
    
    private final String displayName;
    private final int level;
    
    RequestPriority(String displayName, int level) {
        this.displayName = displayName;
        this.level = level;
    }
    
    public boolean isHigherThan(RequestPriority other) {
        return this.level > other.level;
    }
} 