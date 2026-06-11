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

public enum SoarExecutionMode {

    SYNC("sync", "Synchronous approval processing with blocking wait"),

    ASYNC("async", "Asynchronous approval processing with persistence"),

    AUTO("auto", "Automatic mode selection based on context");
    
    private final String code;
    private final String description;
    
    SoarExecutionMode(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getDescription() {
        return description;
    }

    public static SoarExecutionMode fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return AUTO;
        }
        
        for (SoarExecutionMode mode : values()) {
            if (mode.code.equalsIgnoreCase(code.trim())) {
                return mode;
            }
        }
        
        return AUTO;
    }

    public boolean isSync() {
        return this == SYNC;
    }

    public boolean isAsync() {
        return this == ASYNC;
    }

    public boolean isAuto() {
        return this == AUTO;
    }
}