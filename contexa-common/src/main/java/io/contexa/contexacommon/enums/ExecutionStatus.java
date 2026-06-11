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
public enum ExecutionStatus {
    PENDING("Pending", "Request is pending"),
    PROCESSING("Processing", "Request is being processed"),
    SUCCESS("Success", "Request completed successfully"),
    PARTIAL_SUCCESS("Partial Success", "Request partially succeeded"),
    COMPLETED("Completed", "Request completed"),
    FAILED("Failed", "Request processing failed"),
    TIMEOUT("Timeout", "Request processing timed out"),
    CANCELLED("Cancelled", "Request was cancelled");
    
    private final String displayName;
    private final String description;
    
    ExecutionStatus(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    public boolean isCompleted() {
        return this == SUCCESS || this == COMPLETED || this == PARTIAL_SUCCESS || this == FAILED || this == TIMEOUT || this == CANCELLED;
    }
    
    public boolean isSuccessful() {
        return this == SUCCESS || this == PARTIAL_SUCCESS;
    }
} 