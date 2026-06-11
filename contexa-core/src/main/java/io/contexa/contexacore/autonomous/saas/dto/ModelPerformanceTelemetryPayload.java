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
package io.contexa.contexacore.autonomous.saas.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ModelPerformanceTelemetryPayload {

    private String telemetryId;
    private LocalDate period;
    private long layer1SampleCount;
    private long layer1EscalationCount;
    private double layer1EscalationRate;
    private long layer1AvgProcessingMs;
    private long layer2SampleCount;
    private long layer2AvgProcessingMs;
    private long blockCount;
    private long challengeCount;
    private double blockRate;
    private double challengeRate;
    private long totalEventCount;
    private int escalateProtectionTriggered;
    private LocalDateTime generatedAt;
}
