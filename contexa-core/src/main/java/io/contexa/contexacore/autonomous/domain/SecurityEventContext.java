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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEventContext {

    private SecurityEvent securityEvent;

    @Builder.Default
    private ProcessingStatus processingStatus = ProcessingStatus.PENDING;

    @Builder.Default
    private ProcessingMetrics processingMetrics = new ProcessingMetrics();

    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    public SecurityEventContext(SecurityEvent securityEvent) {
        this.securityEvent = securityEvent;
        this.processingStatus = ProcessingStatus.PENDING;
        this.processingMetrics = new ProcessingMetrics();
        this.metadata = new HashMap<>();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }
    public enum ProcessingStatus {

        PENDING,

        ANALYZING,

        AWAITING_APPROVAL,

        COMPLETED,

        FAILED,

        SKIPPED
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProcessingMetrics {

        private Long detectionTimeMs;

        private Long analysisTimeMs;

        private Long responseTimeMs;

        private Long totalTimeMs;

        @Builder.Default
        private int retryCount = 0;

        @Builder.Default
        private boolean hasError = false;

        private String errorMessage;

        private String processingNode;
    }

    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put(key, value);
        updateTimestamp();
    }

    public void updateProcessingStatus(ProcessingStatus status) {
        this.processingStatus = status;
        updateTimestamp();
    }

    public void markAsCompleted() {
        this.processingStatus = ProcessingStatus.COMPLETED;
        if (processingMetrics != null && createdAt != null) {
            processingMetrics.setTotalTimeMs(
                Duration.between(createdAt, LocalDateTime.now()).toMillis()
            );
        }
        updateTimestamp();
    }

    public void markAsFailed(String errorMessage) {
        this.processingStatus = ProcessingStatus.FAILED;
        if (processingMetrics == null) {
            processingMetrics = new ProcessingMetrics();
        }
        processingMetrics.setHasError(true);
        processingMetrics.setErrorMessage(errorMessage);
        updateTimestamp();
    }

    private void updateTimestamp() {
        this.updatedAt = LocalDateTime.now();
    }
}
