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
