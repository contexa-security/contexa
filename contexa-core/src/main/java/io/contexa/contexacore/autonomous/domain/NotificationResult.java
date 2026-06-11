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
package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationResult {
    
    private String requestId;
    private boolean success;
    private String message;
    private String errorCode;
    private LocalDateTime timestamp;

    public static NotificationResult success(String requestId, String message) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(true)
            .message(message)
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static NotificationResult failure(String requestId, String errorMessage) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(false)
            .message(errorMessage)
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static NotificationResult failure(String requestId, String errorCode, String errorMessage) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(false)
            .errorCode(errorCode)
            .message(errorMessage)
            .timestamp(LocalDateTime.now())
            .build();
    }
}